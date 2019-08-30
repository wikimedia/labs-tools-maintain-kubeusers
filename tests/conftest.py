# conftest.py
import pytest
from .context import maintain_kubeusers


@pytest.fixture(scope="module")
def vcr_config():
    return {
        # Replace the Authorization request header with "DUMMY" in cassettes
        "filter_headers": [("authorization", "DUMMY")]
    }


@pytest.fixture
def test_user(tmp_path):
    return maintain_kubeusers.User("blurp", 1002, tmp_path)


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
