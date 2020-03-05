from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pytest

from .context import maintain_kubeusers


@pytest.fixture(scope="module")
def api_object(are_we_in_k8s):
    if are_we_in_k8s:
        maintain_kubeusers.k_config.load_incluster_config()
    else:
        maintain_kubeusers.k_config.load_kube_config(
            config_file="tests/dummy_config"
        )
    return maintain_kubeusers.K8sAPI()


@pytest.mark.vcr()
def test_cert_creation(api_object, test_user):
    priv_key = maintain_kubeusers.generate_pk()
    api_object.generate_csr(priv_key, test_user.name)
    cert = api_object.approve_cert(test_user.name)
    cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
    assert isinstance(cert_obj, x509.Certificate)


@pytest.mark.vcr()
def test_tool_user_exists_with_namespace_and_configmap(api_object, test_user):
    priv_key = maintain_kubeusers.generate_pk()
    api_object.generate_csr(priv_key, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    current, _ = api_object.get_current_tool_users()
    assert test_user.name in current


@pytest.mark.vcr()
def test_tool_renewal(api_object, test_user):
    """ To re-record the vcr tape here, you have to have a clean namespace.  """
    """ Once you've recorded the others, run `kubectl delete ns tool-blurp` """
    """ and make sure you delete the cassette for this one """
    priv_key = maintain_kubeusers.generate_pk()
    api_object.generate_csr(priv_key, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    # We have to patch the configmap to be expired
    config_map = maintain_kubeusers.client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=maintain_kubeusers.client.V1ObjectMeta(
            name="maintain-kubeusers"
        ),
        data={
            "status": "user created: {}".format(
                maintain_kubeusers.datetime.utcnow().isoformat()
            ),
            "expires": "2018-08-14T22:31:00",
        },
    )
    api_object.core.patch_namespaced_config_map(
        "maintain-kubeusers", "tool-{}".format(test_user.name), body=config_map
    )
    _, expired = api_object.get_current_tool_users()
    assert test_user.name in expired
    api_object.update_expired_ns(test_user)
    _, expired = api_object.get_current_tool_users()
    assert test_user.name not in expired
