# conftest.py
import pytest
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
    user = User("blurp", 1002, tmp_path)
    user.cert = b"""
-----BEGIN CERTIFICATE-----
Not really a cert
-----END CERTIFICATE-----
"""
    user.pk = generate_pk()
    user.create_homedir()
    user.write_kubeconfig(
        "myserver", "FAKE_CA_DATA==", True
    )
    return user


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
