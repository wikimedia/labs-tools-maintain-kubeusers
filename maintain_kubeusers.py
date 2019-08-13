#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright 2019 Wikimedia Foundation, Inc.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Automate the process of generating user credentials for Toolforge
Kubernetes


 - Get a list of all the users from LDAP
 - Get a list of namespaces/configmaps in k8s for each toolforge user
 - Do a diff, find new users and users with deleted configmaps
 - For each new user or removed configmap:
    - Create new namespace (only for a new user)
    - generate a CSR (including the right group for RBAC/PSP)
    - Validate and approve the CSR
    - Drop the .kube/config file in the tool directory
    - Annotate the namespace with configmap

"""
import argparse
import base64
from datetime import datetime, timezone
import logging
import os

import stat
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import ldap3
import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException


# TODO: Get credentials from mounted svc account not .kube/config
# This makes it all work great with minikube for testing.
config.load_kube_config()


class K8sAPI:
    def __init__(self):
        self.core = client.CoreV1Api()
        self.certs = client.CertificatesV1beta1Api()
        self.rbac = client.RbacAuthorizationV1Api()

    def get_cluster_info(self):
        c_info = self.core.read_namespaced_config_map(
            "cluster-info", "kube-public"
        )
        cl_kubeconfig = yaml.safe_load(c_info.data["kubeconfig"])
        ca_data = cl_kubeconfig["clusters"][0]["cluster"][
            "certificate-authority-data"
        ]
        api_server = cl_kubeconfig["clusters"][0]["cluster"]["server"]
        return api_server, ca_data

    def get_tool_namespaces(self):
        ls = "tenancy=tool"
        resp = self.core.list_namespace(label_selector=ls)
        namespace_objs = resp.items
        return [ns.metadata.name for ns in namespace_objs]

    def _check_confmap(self, ns):
        fs = "metadata.name=maintain-kubeusers"
        yield self.core.list_namespaced_config_map(ns, field_selector=fs).items

    def get_current_tool_users(self):
        # Return all tools that currently have the maintain-kubeusers ConfigMap
        namespaces = self.get_tool_namespaces()
        return [ns[5:] for ns in namespaces if next(self._check_confmap(ns))]

    def create_configmap(self, user):
        """ To be done after all user generation steps are complete """
        config_map = client.V1ConfigMap(
            api_version="v1",
            kind="ConfigMap",
            metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
            data={
                "status": "user created: {}".format(
                    datetime.utcnow().isoformat()
                )
            },
        )
        resp = self.core.create_namespaced_config_map(
            "tool-{}".format(user), body=config_map
        )
        return resp.metadata.name

    def generate_csr(self, private_key, user):
        # The CSR must include the groups (which are org fields)
        # and CN of the user

        # TODO: exception handling
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.ORGANIZATION_NAME, u"toolforge"
                        ),
                        x509.NameAttribute(NameOID.COMMON_NAME, user),
                    ]
                )
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        b64_csr = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM))
        csr_spec = client.V1beta1CertificateSigningRequestSpec(
            request=b64_csr.decode("utf-8"),
            groups=["system:authenticated", "toolforge"],
            usages=["digital signature", "key encipherment", "client auth"],
        )
        csr_body = client.V1beta1CertificateSigningRequest(
            api_version="certificates.k8s.io/v1beta1",
            kind="CertificateSigningRequest",
            metadata=client.V1ObjectMeta(name="tool-{}".format(user)),
            spec=csr_spec,
        )
        self.certs.create_certificate_signing_request(body=csr_body)
        return

    def approve_cert(self, user):
        """ Approve the CSR and return a cert that can be used """
        # TODO: exception handling
        body = self.certs.read_certificate_signing_request_status(
            "tool-{}".format(user)
        )
        # create an approval condition
        approval_condition = client.V1beta1CertificateSigningRequestCondition(
            last_update_time=datetime.now(timezone.utc).astimezone(),
            message="This certificate was approved by maintain_kubeusers",
            reason="Authorized User",
            type="Approved",
        )
        # patch the existing `body` with the new conditions
        # you might want to append the new conditions to the existing ones
        body.status.conditions = [approval_condition]
        # Patch the Kubernetes CSR object in the certs API
        # The method called to the API is very confusingly named
        _ = self.certs.replace_certificate_signing_request_approval(
            "tool-{}".format(user), body
        )
        # There is a small delay in filling the certificate field, it seems.
        time.sleep(1)
        api_response = self.certs.read_certificate_signing_request(
            "tool-{}".format(user)
        )
        if api_response.status.certificate is not None:
            # Get the actual cert
            cert = base64.b64decode(api_response.status.certificate)
            # Clean up the API
            self.certs.delete_certificate_signing_request(
                "tool-{}".format(user), body=client.V1DeleteOptions()
            )
            return cert
        else:
            logging.error("Certificate creation stalled or failed for %s", user)

    def create_namespace(self, user):
        """
        Creates a namespace for the given user if it doesn't exist
        """
        try:
            _ = self.core.create_namespace(
                body=client.V1Namespace(
                    api_version="v1",
                    kind="Namespace",
                    metadata=client.V1ObjectMeta(
                        name="tool-{}".format(user),
                        labels={
                            "name": "tool-{}".format(user),
                            "tenancy": "tool",
                        },
                    ),
                )
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("Namespace tool-%s already exists", user)
                return

            logging.error("Could not create namespace for %s", user)
            raise

    def process_rbac(self, user):
        # "edit" is a default clusterrole that basically implies
        # write access to most resources, including volumes.
        # It does not include changing roles or bindings or PSPs.
        # PSPs should override most volume functionality.
        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="{}-tool-binding".format(user),
                        namespace="tool-{}".format(user),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="ClusterRole",
                        name="edit",
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name="blurp",
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("RoleBinding %s-tool-binding already exists", user)
                return

            logging.error("Could not create rolebinding for %s", user)
            raise

    def add_user_access(self, username):
        self.create_namespace(username)
        self.process_rbac(username)
        self.create_configmap(username)


class User:
    """ Simple user object kept intentionally light-weight """

    def __init__(self, name, id, home):
        self.name = name
        self.id = id
        self.home = home


def generate_pk():
    # Simple rsa PK generation
    return rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )


def write_certs(location, cert_str, priv_key, user):
    # TODO: Set the gid to the user.id
    try:
        # The x.509 cert is already ready to write
        crt_path = os.path.join(location, "client.crt")
        with open(crt_path, "wb") as cert_file:
            cert_file.write(cert_str)
        os.chown(crt_path, int(user.id), -1)
        os.chmod(crt_path, 0o400)

        # The private key is an object and needs serialization
        key_path = os.path.join(location, "client.key")
        with open(key_path, "wb") as key_file:
            key_file.write(
                priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.chown(key_path, int(user.id), -1)
        os.chmod(key_path, 0o400)
    except Exception:
        logging.warning(
            "Path %s is not writable or failed to store certs somehow", location
        )
        raise


def get_tools_from_ldap(conn, projectname):
    """
    Builds list of all tools from LDAP
    """
    tools = {}
    entries = conn.extend.standard.paged_search(
        "ou=people,ou=servicegroups,dc=wikimedia,dc=org",
        "(&(objectClass=posixAccount)(cn={}.*))".format(projectname),
        search_scope=ldap3.SUBTREE,
        attributes=["cn", "uidNumber", "homeDirectory"],
        time_limit=5,
        paged_size=500,
    )
    for entry in entries:
        attrs = entry["attributes"]
        tool = User(
            attrs["cn"][0][len(projectname) + 1 :],
            attrs["uidNumber"],
            attrs["homeDirectory"],
        )
        tools[tool.name] = tool

    return tools


def write_kubeconfig(user, api_server, ca_data):
    """
    Write an appropriate .kube/config for given user to access given api server.
    """
    dirpath = os.path.join(user.home, ".kube")
    certpath = os.path.join(user.home, ".toolskube")
    certfile = os.path.join(certpath, "client.crt")
    keyfile = os.path.join(certpath, "client.key")
    path = os.path.join(dirpath, "config")
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "cluster": {
                    "server": api_server,
                    "certificate-authority-data": ca_data,
                },
                "name": "default",
            }
        ],
        "users": [
            {
                "user": {"client-certificate": certfile, "client-key": keyfile},
                "name": user.name,
            }
        ],
        "contexts": [
            {
                "context": {
                    "cluster": "default",
                    "user": user.name,
                    "namespace": "tool-{}".format(user.name),
                },
                "name": "default",
            }
        ],
        "current-context": "default",
    }
    # exist_ok=True is fine here, and not a security issue (Famous last words?).
    os.makedirs(certpath, mode=0o775, exist_ok=True)
    os.makedirs(dirpath, mode=0o775, exist_ok=True)
    # TODO: change the GID back to user.id
    os.chown(dirpath, int(user.id), -1)
    os.chown(certpath, int(user.id), -1)
    write_certs(certpath, user.cert, user.pk, user)
    f = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW)
    try:
        os.write(
            f, yaml.dump(config, encoding="utf-8", default_flow_style=False)
        )
        # uid == gid
        os.fchown(f, int(user.id), -1)
        os.fchmod(f, 0o400)
        logging.info("Wrote config in %s", path)
    except os.error:
        logging.exception("Error creating %s", path)
        raise
    finally:
        os.close(f)


def create_homedir(user):
    """
    Create homedirs for new users

    """
    if not os.path.exists(user.home):
        # Try to not touch it if it already exists
        # This prevents us from messing with permissions while also
        # not crashing if homedirs already do exist
        # This also protects against the race exploit that can be done
        # by having a symlink from /data/project/$username point as a symlink
        # to anywhere else. The ordering we have here prevents it - if
        # it already exists in the race between the 'exists' check and
        # the makedirs,
        # we will just fail. Then we switch mode but not ownership, so attacker
        # can not just delete and create a symlink to wherever. The chown
        # happens last, so should be ok.

        os.makedirs(user.home, mode=0o775, exist_ok=False)
        os.chmod(user.home, 0o775 | stat.S_ISGID)
        os.chown(user.home, int(user.id), int(user.id))

        logs_dir = os.path.join(user.home, "logs")
        os.makedirs(logs_dir, mode=0o775, exist_ok=False)
        os.chmod(logs_dir, 0o775 | stat.S_ISGID)
        os.chown(user.home, int(user.id), int(user.id))
    else:
        logging.info("Homedir already exists for %s", user.home)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--ldapconfig",
        help="Path to YAML LDAP config file",
        default="/etc/ldap.yaml",
    )
    argparser.add_argument(
        "--debug", help="Turn on debug logging", action="store_true"
    )
    argparser.add_argument(
        "--project",
        help="Project name to fetch LDAP users from",
        default="tools",
    )
    argparser.add_argument(
        "--interval", help="Seconds between between runs", default=60
    )
    argparser.add_argument(
        "--once", help="Run once and exit", action="store_true"
    )
    argparser.add_argument(
        "kubernetes_api_url", help="Full URL of Kubernetes API"
    )

    args = argparser.parse_args()

    loglvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format="%(message)s", level=loglvl)

    with open(args.ldapconfig, encoding="utf-8") as f:
        ldapconfig = yaml.safe_load(f)

    k8s_api = K8sAPI()
    api_server, ca_data = k8s_api.get_cluster_info()
    cur_users = k8s_api.get_current_tool_users()

    while True:
        logging.info("starting a run")
        servers = ldap3.ServerPool(
            [ldap3.Server(s, connect_timeout=1) for s in ldapconfig["servers"]],
            ldap3.ROUND_ROBIN,
            active=True,
            exhaust=True,
        )
        # TODO: use read_timeout on the connection
        with ldap3.Connection(
            servers,
            read_only=True,
            user=ldapconfig["user"],
            auto_bind=True,
            password=ldapconfig["password"],
            raise_exceptions=True,
        ) as conn:
            tools = get_tools_from_ldap(conn, args.project)

        new_tools = set([tool.name for tool in tools.values()]) - set(cur_users)
        if new_tools:
            for tool_name in new_tools:
                tools[tool_name].pk = generate_pk()
                k8s_api.generate_csr(tools[tool_name].pk, tool_name)
                tools[tool_name].cert = k8s_api.approve_cert(tool_name)
                create_homedir(tools[tool_name])
                write_kubeconfig(tools[tool_name], api_server, ca_data)
                k8s_api.add_user_access(tool_name)
                logging.info("Provisioned creds for tool %s", tool_name)

        logging.info("finished run, wrote %s new accounts", len(new_tools))

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
