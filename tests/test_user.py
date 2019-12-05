
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
