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
from datetime import datetime, timezone, timedelta
import fcntl
import logging
import os
from pathlib import Path
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


class K8sAPI:
    def __init__(self):
        self.core = client.CoreV1Api()
        self.certs = client.CertificatesV1beta1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.extensions = client.ExtensionsV1beta1Api()
        self.settings_api = client.SettingsV1alpha1Api()

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
        return self.core.list_namespaced_config_map(ns, field_selector=fs).items

    def get_current_tool_users(self):
        # Return all tools that currently have the maintain-kubeusers ConfigMap
        # and tools whose certs expire in 30 days
        namespaces = self.get_tool_namespaces()
        current = []
        expiring = []
        test_time = datetime.utcnow() + timedelta(days=30)
        for ns in namespaces:
            cm_list = self._check_confmap(ns)
            if cm_list:
                current.append(ns[5:])
                expiry_time = datetime.strptime(
                    cm_list[0].data["expires"], "%Y-%m-%dT%H:%M:%S"
                )
                if expiry_time <= test_time:
                    expiring.append(ns[5:])

        return current, expiring

    def create_configmap(self, user):
        """ To be done after all user generation steps are complete """
        cert_o = x509.load_pem_x509_certificate(user.cert, default_backend())
        expires = cert_o.not_valid_after
        config_map = client.V1ConfigMap(
            api_version="v1",
            kind="ConfigMap",
            metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
            data={
                "status": "user created: {}".format(
                    datetime.utcnow().isoformat()
                ),
                "expires": expires.isoformat(),
            },
        )
        resp = self.core.create_namespaced_config_map(
            "tool-{}".format(user.name), body=config_map
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

    def create_presets(self, user):
        try:
            _ = self.settings_api.create_namespaced_pod_preset(
                namespace="tool-{}".format(user),
                body=client.V1alpha1PodPreset(
                    api_version="settings.k8s.io/v1alpha1",
                    kind="PodPreset",
                    metadata=client.V1ObjectMeta(name="mount-toolforge-vols"),
                    spec=client.V1alpha1PodPresetSpec(
                        selector=client.V1LabelSelector(
                            match_labels={
                                "toolforge": "tool"
                            }
                        ),
                        env=[
                            client.V1EnvVar(
                                name="HOME",
                                value="/data/project/{}".format(user)
                            ),
                        ],
                        volumes=[
                            client.V1Volume(
                                name="dumps",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/public/dumps", type="Directory"
                                ),
                            ),
                            client.V1Volume(
                                name="home",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/data/project", type="Directory"
                                ),
                            ),
                            client.V1Volume(
                                name="wmcs-project",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/etc/wmcs-project", type="File"
                                ),
                            ),
                            client.V1Volume(
                                name="scratch",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/data/scratch", type="Directory"
                                ),
                            ),
                            client.V1Volume(
                                name="etcldap-conf",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/etc/ldap.conf", type="File"
                                ),
                            ),
                            client.V1Volume(
                                name="etcldap-yaml",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/etc/ldap.yaml", type="File"
                                ),
                            ),
                            client.V1Volume(
                                name="etcnovaobserver-yaml",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/etc/novaobserver.yaml", type="File"
                                ),
                            ),
                            client.V1Volume(
                                name="sssd-pipes",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/var/lib/sss/pipes", type="Directory"
                                ),
                            ),
                        ],
                        volume_mounts=[
                            client.V1VolumeMount(
                                name="dumps",
                                mount_path="/public/dumps",
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="home", mount_path="/data/project"
                            ),
                            client.V1VolumeMount(
                                name="wmcs-project",
                                mount_path="/etc/wmcs-project",
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="scratch", mount_path="/data/scratch"
                            ),
                            client.V1VolumeMount(
                                name="etcldap-conf",
                                mount_path="/etc/ldap.conf",
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="etcldap-yaml",
                                mount_path="/etc/ldap.yaml",
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="etcnovaobserver-yaml",
                                mount_path="/etc/novaobserver.yaml",
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="sssd-pipes",
                                mount_path="/var/lib/sss/pipes",
                            ),
                        ],
                    ),
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "PodPreset mount-toolforge-vols in tool-%s already exists",
                    user,
                )
                return

            logging.error(
                "Could not create PodPreset mount-toolforge-vols for %s", user
            )
            raise

    def create_namespace(self, user):
        """
        Creates a namespace for the given user if it doesn't exist
        """
        namestr = "tool-{}".format(user)
        try:
            _ = self.core.create_namespace(
                body=client.V1Namespace(
                    api_version="v1",
                    kind="Namespace",
                    metadata=client.V1ObjectMeta(
                        name=namestr,
                        labels={"name": namestr, "tenancy": "tool"},
                    ),
                )
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("Namespace tool-%s already exists", user)
                return

            logging.error("Could not create namespace for %s", user)
            raise

        # The above will shortcircuit this function before altering quotas
        # Define default quotas for new namespaces only
        _ = self.core.create_namespaced_resource_quota(
            namespace=namestr,
            body=client.V1ResourceQuota(
                api_version="v1",
                kind="ResourceQuota",
                metadata=client.V1ObjectMeta(name=namestr),
                spec=client.V1ResourceQuotaSpec(
                    hard={
                        "requests.cpu": "2",
                        "requests.memory": "6Gi",
                        "limits.cpu": "2",
                        "limits.memory": "8Gi",
                        "pods": "4",
                        "services": "1",
                        "services.nodeports": "0",
                        "replicationcontrollers": "1",
                        "secrets": "10",
                        "configmaps": "10",
                        "persistentvolumeclaims": "3",
                    }
                ),
            ),
        )
        _ = self.core.create_namespaced_limit_range(
            namespace=namestr,
            body=client.V1LimitRange(
                api_version="v1",
                kind="LimitRange",
                metadata=client.V1ObjectMeta(name=namestr),
                spec=client.V1LimitRangeSpec(
                    limits=[
                        client.V1LimitRangeItem(
                            default={"cpu": "500m", "memory": "512Mi"},
                            default_request={"cpu": "250m", "memory": "256Mi"},
                            type="Container",
                            max={"cpu": "1", "memory": "4Gi"},
                            min={"cpu": "100m", "memory": "100Mi"},
                        )
                    ]
                ),
            ),
        )

    def update_expired_ns(self, user):
        """ Patch the existing NS for the new certificate exipration """
        cert_o = x509.load_pem_x509_certificate(user.cert, default_backend())
        expires = cert_o.not_valid_after
        config_map = client.V1ConfigMap(
            api_version="v1",
            kind="ConfigMap",
            metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
            data={
                "status": "user created: {}".format(
                    datetime.utcnow().isoformat()
                ),
                "expires": expires.isoformat(),
            },
        )
        resp = self.core.patch_namespaced_config_map(
            "maintain-kubeusers", "tool-{}".format(user.name), body=config_map
        )
        return resp.metadata.name

    def generate_psp(self, user):
        policy = client.ExtensionsV1beta1PodSecurityPolicy(
            api_version="extensions/v1beta1",
            kind="PodSecurityPolicy",
            metadata=client.V1ObjectMeta(
                name="tool-{}-psp".format(user.name),
                annotations={
                    "seccomp.security.alpha.kubernetes.io/allowedProfileNames": "runtime/default",  # noqa: E501
                    "seccomp.security.alpha.kubernetes.io/defaultProfileName": "runtime/default",  # noqa: E501
                },
            ),
            spec=client.ExtensionsV1beta1PodSecurityPolicySpec(
                allow_privilege_escalation=False,
                fs_group=client.ExtensionsV1beta1FSGroupStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.ExtensionsV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                host_ipc=False,
                host_network=False,
                host_pid=False,
                privileged=False,
                read_only_root_filesystem=False,
                run_as_user=client.ExtensionsV1beta1RunAsUserStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.ExtensionsV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                se_linux=client.ExtensionsV1beta1SELinuxStrategyOptions(
                    rule="RunAsAny"
                ),
                run_as_group=client.ExtensionsV1beta1RunAsGroupStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.ExtensionsV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                supplemental_groups=client.ExtensionsV1beta1SupplementalGroupsStrategyOptions(  # noqa: E501
                    rule="MustRunAs",
                    ranges=[client.ExtensionsV1beta1IDRange(min=1, max=65535)],
                ),
                volumes=[
                    "configMap",
                    "downwardAPI",
                    "emptyDir",
                    "projected",
                    "secret",
                    "hostPath",
                    "persistentVolumeClaim",
                ],
                allowed_host_paths=[
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/var/lib/sss/pipes", read_only=False
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/data/project", read_only=False
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/data/scratch", read_only=False
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/public/dumps", read_only=True
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/etc/wmcs-project", read_only=True
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/etc/ldap.yaml", read_only=True
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/etc/novaobserver.yaml", read_only=True
                    ),
                    client.ExtensionsV1beta1AllowedHostPath(
                        path_prefix="/etc/ldap.conf", read_only=True
                    ),
                ],
            ),
        )
        try:
            _ = self.extensions.create_pod_security_policy(policy)
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "PodSecurityPolicy tool-%s-psp already exists", user.name
                )
                return

            logging.error("Could not create podsecuritypolicy for %s", user)
            raise

    def process_rbac(self, user):
        try:
            _ = self.rbac.create_namespaced_role(
                namespace="tool-{}".format(user),
                body=client.V1Role(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="Role",
                    metadata=client.V1ObjectMeta(
                        name="tool-{}-psp".format(user),
                        namespace="tool-{}".format(user),
                    ),
                    rules=[
                        client.V1PolicyRule(
                            api_groups=["extensions"],
                            resource_names=["tool-{}-psp".format(user)],
                            resources=["podsecuritypolicies"],
                            verbs=["use"],
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("Role tool-%s-psp already exists", user)
                return

            logging.error("Could not create psp role for %s", user)
            raise

        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="tool-{}-psp-binding".format(user),
                        namespace="tool-{}".format(user),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="Role",
                        name="tool-{}-psp".format(user),
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=user,
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "RoleBinding tool-%s-psp-binding already exists", user
                )
                return

            logging.error("Could not create psp rolebinding for %s", user)
            raise

        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="default-{}-psp-binding".format(user),
                        namespace="tool-{}".format(user),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="Role",
                        name="tool-{}-psp".format(user),
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="ServiceAccount",
                            name="default",
                            namespace="tool-{}".format(user),
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "RoleBinding default-%s-psp-binding already exists", user
                )
                return

            logging.error(
                (
                    "Could not create psp rolebinding for tool-%s:default "
                    "serviceaccount"
                ),
                user,
            )
            raise

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
                        name="tools-user",
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=user,
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

    def add_user_access(self, user):
        self.generate_psp(user)
        self.create_namespace(user.name)
        self.create_presets(user.name)
        self.process_rbac(user.name)
        self.create_configmap(user)


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
    try:
        # The x.509 cert is already ready to write
        crt_path = os.path.join(location, "client.crt")
        with open(crt_path, "wb") as cert_file:
            cert_file.write(cert_str)
        os.chown(crt_path, int(user.id), int(user.id))
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
        os.chown(key_path, int(user.id), int(user.id))
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


def append_config(user, config, api_server, ca_data, keyfile, certfile):
    config["clusters"].append(
        {
            "cluster": {
                "server": api_server,
                "certificate-authority-data": ca_data,
            },
            "name": "toolforge",
        }
    )
    config["users"].append(
        {
            "user": {"client-certificate": certfile, "client-key": keyfile},
            "name": "tf-{}".format(user.name),
        }
    )
    config["contexts"].append(
        {
            "context": {
                "cluster": "toolforge",
                "user": "tf-{}".format(user.name),
                "namespace": "tool-{}".format(user.name),
            },
            "name": "toolforge",
        }
    )


def merge_config(user, config, api_server, ca_data, keyfile, certfile):
    for i in range(len(config["clusters"])):
        if config["clusters"][i]["name"] == "toolforge":
            config["clusters"][i] = {
                "cluster": {
                    "server": api_server,
                    "certificate-authority-data": ca_data,
                },
                "name": "toolforge",
            }
    for i in range(len(config["users"])):
        if "client-certificate" in config["users"][i]["user"]:
            config["users"][i] = {
                "user": {"client-certificate": certfile, "client-key": keyfile},
                "name": "tf-{}".format(user.name),
            }
    for i in range(len(config["contexts"])):
        if config["contexts"][i]["name"] == "toolforge":
            config["contexts"][i] = {
                "context": {
                    "cluster": "toolforge",
                    "user": "tf-{}".format(user.name),
                    "namespace": "tool-{}".format(user.name),
                },
                "name": "toolforge",
            }


def write_kubeconfig(user, api_server, ca_data, gentle):
    """
    Write or merge an appropriate .kube/config for given user to access given
    api server.
    """
    dirpath = os.path.join(user.home, ".kube")
    certpath = os.path.join(user.home, ".toolskube")
    certfile = os.path.join(certpath, "client.crt")
    keyfile = os.path.join(certpath, "client.key")
    path = os.path.join(dirpath, "config")
    current_context = "default" if gentle else "toolforge"
    # If the path exists, merge the configs and do not force the switch to this
    # cluster
    if os.path.isfile(path):
        # If this is not yaml (JSON is YAML), fail with warning on this user.
        try:
            with open(path) as oldpath:
                config = yaml.safe_load(oldpath)
        except Exception:
            logging.warning("Invalid config at %s!", path)
            return

        # At least make sure we are using valid required keys before proceeding
        if all(
            k in config
            for k in (
                "apiVersion",
                "kind",
                "clusters",
                "users",
                "contexts",
                "current-context",
            )
        ):
            # First check if we are using a "virgin" Toolforge 1.0 config
            is_new = True
            for i in range(len(config["clusters"])):
                if config["clusters"][i]["name"] == "toolforge":
                    is_new = False

            if is_new:
                # Add the new context for future use and move along
                append_config(
                    user, config, api_server, ca_data, keyfile, certfile
                )
            else:
                # We need to overwrite only the "toolforge" configs
                merge_config(
                    user, config, api_server, ca_data, keyfile, certfile
                )
        else:
            # Don't touch invalid configs
            logging.warning("Invalid config at %s!", path)
            return

    else:
        # Declare a config, then append the new material
        config = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [],
            "users": [],
            "contexts": [],
            "current-context": current_context,
        }
        append_config(user, config, api_server, ca_data, keyfile, certfile)

    # exist_ok=True is fine here, and not a security issue (Famous last words?).
    os.makedirs(certpath, mode=0o775, exist_ok=True)
    os.makedirs(dirpath, mode=0o775, exist_ok=True)
    os.chown(dirpath, int(user.id), int(user.id))
    os.chown(certpath, int(user.id), int(user.id))
    write_certs(certpath, user.cert, user.pk, user)
    f = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        os.write(
            f,
            yaml.safe_dump(config, encoding="utf-8", default_flow_style=False),
        )
        fcntl.flock(f, fcntl.LOCK_UN)
        # uid == gid
        os.fchown(f, int(user.id), int(user.id))
        os.fchmod(f, 0o600)
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
        "--local",
        help="Specifies this is not running in Kubernetes (for debugging)",
        action="store_true",
    )

    argparser.add_argument(
        "--gentle-mode",
        help=(
            "Before general release, keep current context set to default "
            "while the new Kubernetes cluster is considered opt-in"
        ),
        action="store_true",
    )

    args = argparser.parse_args()

    loglvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format="%(message)s", level=loglvl)

    with open(args.ldapconfig, encoding="utf-8") as f:
        ldapconfig = yaml.safe_load(f)

    if args.local:
        config.load_kube_config()
    else:
        config.load_incluster_config()

    k8s_api = K8sAPI()
    api_server, ca_data = k8s_api.get_cluster_info()

    while True:
        logging.info("starting a run")
        # Touch a temp file for a Kubernetes liveness check to prevent hangs
        Path("/tmp/run.check").touch()
        cur_users, expiring_users = k8s_api.get_current_tool_users()
        servers = ldap3.ServerPool(
            [ldap3.Server(s, connect_timeout=1) for s in ldapconfig["servers"]],
            ldap3.ROUND_ROBIN,
            active=True,
            exhaust=True,
        )
        with ldap3.Connection(
            servers,
            read_only=True,
            user=ldapconfig["user"],
            auto_bind=True,
            password=ldapconfig["password"],
            raise_exceptions=True,
            receive_timeout=60,
        ) as conn:
            tools = get_tools_from_ldap(conn, args.project)

        new_tools = set([tool.name for tool in tools.values()]) - set(cur_users)
        if new_tools:
            for tool_name in new_tools:
                tools[tool_name].pk = generate_pk()
                k8s_api.generate_csr(tools[tool_name].pk, tool_name)
                tools[tool_name].cert = k8s_api.approve_cert(tool_name)
                create_homedir(tools[tool_name])
                write_kubeconfig(
                    tools[tool_name], api_server, ca_data, args.gentle_mode
                )
                k8s_api.add_user_access(tools[tool_name])
                logging.info("Provisioned creds for tool %s", tool_name)

        logging.info("finished run, wrote %s new accounts", len(new_tools))

        if expiring_users:
            for tool_name in expiring_users:
                tools[tool_name].pk = generate_pk()
                k8s_api.generate_csr(tools[tool_name].pk, tool_name)
                tools[tool_name].cert = k8s_api.approve_cert(tool_name)
                create_homedir(tools[tool_name])
                write_kubeconfig(
                    tools[tool_name], api_server, ca_data, args.gentle_mode
                )
                k8s_api.update_expired_ns(tools[tool_name])
                logging.info("Renewed creds for tool %s", tool_name)

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
