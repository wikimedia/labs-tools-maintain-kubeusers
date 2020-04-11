from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import time
import pytest
from .context import K8sAPI, k_config, client, ApiException


@pytest.fixture()
def api_object(are_we_in_k8s, test_user):
    if are_we_in_k8s:
        k_config.load_incluster_config()
    else:
        k_config.load_kube_config(config_file="tests/dummy_config")
    api = K8sAPI()
    yield api
    # If we created a namespace, delete it to clean up
    try:
        _ = api.core.delete_namespace(
            "tool-{}".format(test_user.name),
            grace_period_seconds=0,
            propagation_policy="Foreground",
        )
    except ApiException:  # If there was no namespace, we are ok with that.
        pass
    # If we created an admin configmap, delete it to clean up
    try:
        _ = api.core.delete_namespaced_config_map(
            "maintain-kubeusers", "maintain-kubeusers",
            grace_period_seconds=0,
            propagation_policy="Foreground",
        )
    except ApiException:  # If there was no namespace, we are ok with that.
        pass
    try:
        _ = api.policy.delete_pod_security_policy(
            "tool-{}-psp".format(test_user.name),
            grace_period_seconds=0,
            propagation_policy="Foreground",
        )
    except ApiException:  # If there was no PSP, we are ok with that.
        pass
    # If recording the cassettes, you need to wait for namespaces to be deleted
    if are_we_in_k8s:
        time.sleep(5)


@pytest.mark.vcr()
def test_cert_creation(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    cert = api_object.approve_cert(test_user.name)
    cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
    assert isinstance(cert_obj, x509.Certificate)


@pytest.mark.vcr()
def test_tool_user_exists_with_namespace_and_configmap(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    current, _ = api_object.get_current_users()
    assert test_user.name in current["tools"]


@pytest.mark.vcr()
def test_tool_renewal(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    # We have to patch the configmap to be expired
    config_map = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
        data={
            "status": "user created: {}".format(datetime.utcnow().isoformat()),
            "expires": "2018-08-14T22:31:00",
        },
    )
    api_object.core.patch_namespaced_config_map(
        "maintain-kubeusers", "tool-{}".format(test_user.name), body=config_map
    )
    _, expired = api_object.get_current_users()
    assert test_user.name in expired["tools"]
    api_object.update_expired_ns(test_user)
    _, expired = api_object.get_current_users()
    assert test_user.name not in expired["tools"]


@pytest.mark.vcr()
def test_test_admin_exists_with_configmap(api_object, test_admin):
    api_object.generate_csr(test_admin.pk, test_admin.name)
    test_admin.cert = api_object.approve_cert(test_admin.name)
    api_object.add_user_access(test_admin)
    current, _ = api_object.get_current_users()
    assert test_admin.name in current["admins"]


@pytest.mark.vcr()
def test_admin_renewal(api_object, test_admin):
    api_object.generate_csr(test_admin.pk, test_admin.name)
    test_admin.cert = api_object.approve_cert(test_admin.name)
    api_object.add_user_access(test_admin)
    # We have to patch the configmap to be expired
    patch_data = {"data": {test_admin.name: "2018-08-14T22:31:00"}}
    api_object.core.patch_namespaced_config_map(
        "maintain-kubeusers", "maintain-kubeusers", body=patch_data
    )
    _, expired = api_object.get_current_users()
    assert test_admin.name in expired["admins"]
    api_object.update_expired_ns(test_admin)
    _, expired = api_object.get_current_users()
    assert test_admin.name not in expired["admins"]
