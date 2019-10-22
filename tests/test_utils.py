import pytest

from .context import maintain_kubeusers


@pytest.fixture(scope="module")
def api_object():
    maintain_kubeusers.config.load_kube_config()
    return maintain_kubeusers.K8sAPI()


def test_home_dir_utils(test_user, mocker):
    mocker.patch("os.chown", autospec=True)
    mocker.patch("os.fchown", autospec=True)
    test_user.cert = b"""
-----BEGIN CERTIFICATE-----
Not really a cert
-----END CERTIFICATE-----
"""
    test_user.pk = maintain_kubeusers.generate_pk()
    maintain_kubeusers.create_homedir(test_user)
    maintain_kubeusers.write_kubeconfig(
        test_user, "myserver", "FAKE_CA_DATA==", False
    )
    kube_conf = test_user.home / ".kube" / "config"
    certs_dir = test_user.home / ".toolskube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".toolskube/client.crt" in kube_conf.read_text()
