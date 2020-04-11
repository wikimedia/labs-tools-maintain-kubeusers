import base64
from datetime import datetime, timezone, timedelta
import logging
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import yaml
from kubernetes import client
from kubernetes.client.rest import ApiException

from maintain_kubeusers.user import User


class K8sAPI:
    def __init__(self):
        self.core = client.CoreV1Api()
        self.certs = client.CertificatesV1beta1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.settings_api = client.SettingsV1alpha1Api()
        self.policy = client.PolicyV1beta1Api()

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

    def get_current_users(self, admins=False):
        # Return all tools that currently have the maintain-kubeusers ConfigMap
        # and tools whose certs expire in 30 days
        namespaces = self.get_tool_namespaces()
        current_tools = []
        current_admins = []
        expiring_tools = []
        expiring_admins = []
        test_time = datetime.utcnow() + timedelta(days=30)
        if not admins:
            for ns in namespaces:
                cm_list = self._check_confmap(ns)
                if cm_list:
                    current_tools.append(ns[5:])
                    expiry_time = datetime.strptime(
                        cm_list[0].data["expires"], "%Y-%m-%dT%H:%M:%S"
                    )
                    if expiry_time <= test_time:
                        expiring_tools.append(ns[5:])

        adm_cm_list = self._check_confmap("maintain-kubeusers")
        if adm_cm_list:
            for admin_name, admin_exp in adm_cm_list[0].data.items():
                expiry_time = datetime.strptime(admin_exp, "%Y-%m-%dT%H:%M:%S")
                current_admins.append(admin_name)
                if expiry_time <= test_time:
                    expiring_admins.append(admin_name)

        return (
            {"tools": current_tools, "admins": current_admins},
            {"tools": expiring_tools, "admins": expiring_admins},
        )

    def create_configmap(self, user: User) -> str:
        """ To be done after all user generation steps are complete """
        cert_o = x509.load_pem_x509_certificate(user.cert, default_backend())
        expires = cert_o.not_valid_after
        if user.admin:
            cm_data = {user.name: expires.isoformat()}
            admin_cm_list = self._check_confmap("maintain-kubeusers")
            if not admin_cm_list:
                config_map = client.V1ConfigMap(
                    api_version="v1",
                    kind="ConfigMap",
                    metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
                    data=cm_data,
                )
                resp = self.core.create_namespaced_config_map(
                    "maintain-kubeusers", body=config_map
                )
                return resp.metadata.name

            resp = self.core.patch_namespaced_config_map(
                "maintain-kubeusers", "maintain-kubeusers", {"data": cm_data}
            )
            return resp.metadata.name

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

    def generate_csr(self, private_key, user, admin=False):
        # The CSR must include the groups (which are org fields)
        # and CN of the user
        org_name = "admins" if admin else "toolforge"
        # TODO: exception handling
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                        x509.NameAttribute(NameOID.COMMON_NAME, user),
                    ]
                )
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        b64_csr = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM))
        csr_spec = client.V1beta1CertificateSigningRequestSpec(
            request=b64_csr.decode("utf-8"),
            groups=["system:authenticated", org_name],
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

    def approve_cert(self, user_name, admin=False):
        """ Approve the CSR and return a cert that can be used """
        # TODO: exception handling
        user = user_name if admin else "tool-{}".format(user_name)
        body = self.certs.read_certificate_signing_request_status(user)
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
        _ = self.certs.replace_certificate_signing_request_approval(user, body)
        # There is a small delay in filling the certificate field, it seems.
        time.sleep(1)
        api_response = self.certs.read_certificate_signing_request(user)
        if api_response.status.certificate is not None:
            # Get the actual cert
            cert = base64.b64decode(api_response.status.certificate)
            # Clean up the API
            self.certs.delete_certificate_signing_request(
                user, body=client.V1DeleteOptions()
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
                            match_labels={"toolforge": "tool"}
                        ),
                        env=[
                            client.V1EnvVar(
                                name="HOME",
                                value="/data/project/{}".format(user),
                            )
                        ],
                        volumes=[
                            client.V1Volume(
                                name="dumps",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/public/dumps", type="Directory"
                                ),
                            ),
                            client.V1Volume(
                                name="dumpsrc1",
                                host_path=client.V1HostPathVolumeSource(
                                    path=(
                                        "/mnt/nfs/dumps-"
                                        "labstore1007.wikimedia.org"
                                    ),
                                    type="Directory",
                                ),
                            ),
                            client.V1Volume(
                                name="dumpsrc2",
                                host_path=client.V1HostPathVolumeSource(
                                    path=(
                                        "/mnt/nfs/dumps-"
                                        "labstore1006.wikimedia.org"
                                    ),
                                    type="Directory",
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
                                name="dumpsrc1",
                                mount_path=(
                                    "/mnt/nfs/dumps-"
                                    "labstore1007.wikimedia.orgs"
                                ),
                                read_only=True,
                            ),
                            client.V1VolumeMount(
                                name="dumpsrc2",
                                mount_path=(
                                    "/mnt/nfs/dumps-"
                                    "labstore1006.wikimedia.org"
                                ),
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
                            default_request={"cpu": "150m", "memory": "256Mi"},
                            type="Container",
                            max={"cpu": "1", "memory": "4Gi"},
                            min={"cpu": "50m", "memory": "100Mi"},
                        )
                    ]
                ),
            ),
        )

    def update_expired_ns(self, user):
        """ Patch the existing NS for the new certificate expiration """
        cert_o = x509.load_pem_x509_certificate(user.cert, default_backend())
        expires = cert_o.not_valid_after
        if user.admin:
            namespace = "maintain-kubeusers"
            cm_data = {"data": {user.name: expires.isoformat()}}
            resp = self.core.patch_namespaced_config_map(
                "maintain-kubeusers", "maintain-kubeusers", cm_data
            )
            return resp.metadata.name
        else:
            namespace = "tool-{}".format(user.name)
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
            "maintain-kubeusers", namespace, body=config_map
        )
        return resp.metadata.name

    def generate_psp(self, user):
        policy = client.PolicyV1beta1PodSecurityPolicy(
            api_version="policy/v1beta1",
            kind="PodSecurityPolicy",
            metadata=client.V1ObjectMeta(
                name="tool-{}-psp".format(user.name),
                annotations={
                    "seccomp.security.alpha.kubernetes.io/allowedProfileNames": "runtime/default",  # noqa: E501
                    "seccomp.security.alpha.kubernetes.io/defaultProfileName": "runtime/default",  # noqa: E501
                },
            ),
            spec=client.PolicyV1beta1PodSecurityPolicySpec(
                allow_privilege_escalation=False,
                fs_group=client.PolicyV1beta1FSGroupStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.PolicyV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                host_ipc=False,
                host_network=False,
                host_pid=False,
                privileged=False,
                required_drop_capabilities=["ALL"],
                read_only_root_filesystem=False,
                run_as_user=client.PolicyV1beta1RunAsUserStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.PolicyV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                se_linux=client.PolicyV1beta1SELinuxStrategyOptions(
                    rule="RunAsAny"
                ),
                run_as_group=client.PolicyV1beta1RunAsGroupStrategyOptions(
                    rule="MustRunAs",
                    ranges=[
                        client.PolicyV1beta1IDRange(
                            max=int(user.id), min=int(user.id)
                        )
                    ],
                ),
                supplemental_groups=client.PolicyV1beta1SupplementalGroupsStrategyOptions(  # noqa: E501
                    rule="MustRunAs",
                    ranges=[client.PolicyV1beta1IDRange(min=1, max=65535)],
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
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/var/lib/sss/pipes", read_only=False
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/data/project", read_only=False
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/data/scratch", read_only=False
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/public/dumps", read_only=True
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/mnt/nfs", read_only=True
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/etc/wmcs-project", read_only=True
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/etc/ldap.yaml", read_only=True
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/etc/novaobserver.yaml", read_only=True
                    ),
                    client.PolicyV1beta1AllowedHostPath(
                        path_prefix="/etc/ldap.conf", read_only=True
                    ),
                ],
            ),
        )
        try:
            _ = self.policy.create_pod_security_policy(policy)
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "PodSecurityPolicy tool-%s-psp already exists", user.name
                )
                return

            logging.error("Could not create podsecuritypolicy for %s", user)
            raise

    def process_rbac(self, user_name):
        try:
            _ = self.rbac.create_namespaced_role(
                namespace="tool-{}".format(user_name),
                body=client.V1Role(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="Role",
                    metadata=client.V1ObjectMeta(
                        name="tool-{}-psp".format(user_name),
                        namespace="tool-{}".format(user_name),
                    ),
                    rules=[
                        client.V1PolicyRule(
                            api_groups=["policy"],
                            resource_names=["tool-{}-psp".format(user_name)],
                            resources=["podsecuritypolicies"],
                            verbs=["use"],
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("Role tool-%s-psp already exists", user_name)
                return

            logging.error("Could not create psp role for %s", user_name)
            raise

        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user_name),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="tool-{}-psp-binding".format(user_name),
                        namespace="tool-{}".format(user_name),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="Role",
                        name="tool-{}-psp".format(user_name),
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=user_name,
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "RoleBinding tool-%s-psp-binding already exists", user_name
                )
                return

            logging.error("Could not create psp rolebinding for %s", user_name)
            raise

        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user_name),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="default-{}-psp-binding".format(user_name),
                        namespace="tool-{}".format(user_name),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="Role",
                        name="tool-{}-psp".format(user_name),
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="ServiceAccount",
                            name="default",
                            namespace="tool-{}".format(user_name),
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "RoleBinding default-%s-psp-binding already exists",
                    user_name,
                )
                return

            logging.error(
                (
                    "Could not create psp rolebinding for tool-%s:default "
                    "serviceaccount"
                ),
                user_name,
            )
            raise

        try:
            _ = self.rbac.create_namespaced_role_binding(
                namespace="tool-{}".format(user_name),
                body=client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="RoleBinding",
                    metadata=client.V1ObjectMeta(
                        name="{}-tool-binding".format(user_name),
                        namespace="tool-{}".format(user_name),
                    ),
                    role_ref=client.V1RoleRef(
                        kind="ClusterRole",
                        name="tools-user",
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=user_name,
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                ),
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info(
                    "RoleBinding %s-tool-binding already exists", user_name
                )
                return

            logging.error("Could not create rolebinding for %s", user_name)
            raise

    def process_admin_rbac(self, username: str) -> None:
        # Let admins read anything
        try:
            _ = self.rbac.create_cluster_role_binding(
                body=client.V1ClusterRoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="ClusterRoleBinding",
                    metadata=client.V1ObjectMeta(name=f"{username}-binding"),
                    role_ref=client.V1RoleRef(
                        kind="ClusterRole",
                        name="view",
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=username,
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                )
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("RoleBinding %s-binding already exists", username)
                return

            logging.error(
                "Could not create clusterrolebinding for %s", username
            )
            raise

        # Also let admins impersonate anything, allowing full sudo access
        try:
            _ = self.rbac.create_cluster_role_binding(
                body=client.V1ClusterRoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    kind="ClusterRoleBinding",
                    metadata=client.V1ObjectMeta(name=f"{username}-binding"),
                    role_ref=client.V1RoleRef(
                        kind="ClusterRole",
                        name="k8s-admin",
                        api_group="rbac.authorization.k8s.io",
                    ),
                    subjects=[
                        client.V1Subject(
                            kind="User",
                            name=username,
                            api_group="rbac.authorization.k8s.io",
                        )
                    ],
                )
            )
        except ApiException as api_ex:
            if api_ex.status == 409 and "AlreadyExists" in api_ex.body:
                logging.info("RoleBinding %s-binding already exists", username)
                return

            logging.error(
                "Could not create clusterrolebinding for %s", username
            )
            raise

    def add_user_access(self, user):
        if not user.admin:
            self.generate_psp(user)
            self.create_namespace(user.name)
            self.create_presets(user.name)
            self.process_rbac(user.name)
        else:
            self.process_admin_rbac(user.name)

        self.create_configmap(user)
