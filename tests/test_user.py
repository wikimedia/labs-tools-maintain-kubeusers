from unittest.mock import patch

from .context import REQUIRED_CONFIG_KEYS


def test_create_user(test_user):
    kube_conf = test_user.home / ".kube" / "config"
    certs_dir = test_user.home / ".toolskube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".toolskube/client.crt" in kube_conf.read_text()


def test_disabled_user(test_disabled_user):
    kube_conf = test_disabled_user.home / ".kube" / "config"
    certs_dir = test_disabled_user.home / ".toolskube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".toolskube/client.crt" in kube_conf.read_text()
    assert test_disabled_user.is_disabled()


def test_admin_user(test_admin):
    kube_conf = test_admin.home / ".kube" / "config"
    certs_dir = test_admin.home / ".admkube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    with patch("os.chown", autospec=True):
        with patch("os.fchown", autospec=True):
            with patch("os.chmod", autospec=True) as chmod_mock:
                test_admin.write_kubeconfig("myserver", "FAKE_CA_DATA==")
                # Admin user creds are read-only to owner, not group
                # pylint: disable=no-member
                chmod_mock.assert_any_call(str(cert), 0o400)
                chmod_mock.assert_any_call(str(key), 0o400)
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".admkube/client.crt" in kube_conf.read_text()
    assert test_admin.is_disabled() is False


def test_write_config_file_truncate(test_user):
    kube_conf = test_user.home / ".kube" / "config"
    # Something that's very long and definitely does not pass YAML validation.
    kube_conf.write_text("NOTYAML:" * 1000)

    assert test_user.read_config_file() == {}

    # Changing permissions needs root which we generally don't have in tests.
    with patch("os.fchown", autospec=True):
        # Write the required keys so config validation does not fail.
        test_user.write_config_file({key: True for key in REQUIRED_CONFIG_KEYS})

    assert "apiVersion" in test_user.read_config_file()
