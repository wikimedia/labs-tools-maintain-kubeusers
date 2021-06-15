# conftest.py
import pytest
import ldap3
from .context import User, generate_pk


@pytest.fixture(scope="module")
def vcr_config():
    return {
        # Replace the Authorization request header with "DUMMY" in cassettes
        "filter_headers": [("authorization", "DUMMY")]
    }


@pytest.fixture
def test_user(tmp_path, mocker):
    mocker.patch("os.chown", autospec=True)
    mocker.patch("os.fchown", autospec=True)
    mocker.patch("os.chmod", autospec=True)
    mocker.patch("os.fchmod", autospec=True)
    user = User(
        "blurp",
        1002,
        tmp_path / "blurp",
        None,
        None,
        False,
        "tools",
    )
    user.cert = b"""
-----BEGIN CERTIFICATE-----
Not really a cert
-----END CERTIFICATE-----
"""
    user.pk = generate_pk()
    user.create_homedir()
    user.write_kubeconfig("myserver", "FAKE_CA_DATA==", True)
    return user


@pytest.fixture
def test_disabled_user(tmp_path, mocker):
    mocker.patch("os.chown", autospec=True)
    mocker.patch("os.fchown", autospec=True)
    mocker.patch("os.chmod", autospec=True)
    mocker.patch("os.fchmod", autospec=True)
    user = User(
        "blorp",
        1002,
        tmp_path / "blorp",
        "000001010000Z",
        "cn=disabled,ou=ppolicies,dc=wikimedia,dc=org",
        False,
        "tools",
    )
    user.cert = b"""
-----BEGIN CERTIFICATE-----
Not really a cert
-----END CERTIFICATE-----
"""
    user.pk = generate_pk()
    user.create_homedir()
    user.write_kubeconfig("myserver", "FAKE_CA_DATA==", True)
    return user


@pytest.fixture
def test_admin(tmp_path, mocker):
    mocker.patch("os.chown", autospec=True)
    mocker.patch("os.fchown", autospec=True)
    mocker.patch("os.chmod", autospec=True)
    admin_user = User("admin", 1003, tmp_path, None, None, True)
    admin_user.cert = b"""
-----BEGIN CERTIFICATE-----
Not really a cert
-----END CERTIFICATE-----
"""
    admin_user.pk = generate_pk()
    return admin_user


def pytest_addoption(parser):
    parser.addoption(
        "--in-k8s",
        action="store_true",
        default=False,
        help="For rebuilding cassettes inside k8s",
    )


@pytest.fixture(scope="session")
def are_we_in_k8s(request):
    return request.config.getoption("--in-k8s")


@pytest.fixture
def ldap_conn():
    server = ldap3.Server("ldap-server.example.com")
    return ldap3.Connection(
        server,
        read_only=True,
        user="cn=test,ou=testprofile,dc=wikimedia,dc=org",
        password="notreal",
        raise_exceptions=True,
        receive_timeout=60,
    )
