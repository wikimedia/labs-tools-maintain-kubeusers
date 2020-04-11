import os


def test_create_user(test_user):
    kube_conf = test_user.home / ".kube" / "config"
    certs_dir = test_user.home / ".toolskube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".toolskube/client.crt" in kube_conf.read_text()


def test_migrate_user(test_user):
    # test_user starts in gentle mode
    kube_conf = test_user.home / ".kube" / "config"
    assert "current-context: default" in kube_conf.read_text()
    # migrate them!
    test_user.switch_context()
    assert "current-context: toolforge" in kube_conf.read_text()


def test_admin_user(test_admin):
    kube_conf = test_admin.home / ".kube" / "config"
    certs_dir = test_admin.home / ".admkube"
    cert = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    test_admin.write_kubeconfig(
        "myserver", "FAKE_CA_DATA==", True
    )
    # Admin user creds are read-only to owner, not group
    os.chmod.assert_any_call(str(cert), 0o400)  # pylint: disable=no-member
    os.chmod.assert_any_call(str(key), 0o400)   # pylint: disable=no-member
    assert "Not really a cert" in cert.read_text()
    assert "PRIVATE KEY" in key.read_text()
    assert ".admkube/client.crt" in kube_conf.read_text()
