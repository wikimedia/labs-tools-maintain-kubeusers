from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pytest

from .context import maintain_kubeusers


@pytest.fixture(scope="module")
def api_object():
    maintain_kubeusers.config.load_kube_config()
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
    api_object.add_user_access(test_user.name)
    assert test_user.name in api_object.get_current_tool_users()
