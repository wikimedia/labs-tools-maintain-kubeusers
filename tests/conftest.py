# conftest.py
import pytest
from .context import maintain_kubeusers


@pytest.fixture(scope='module')
def vcr_config():
    return {
        # Replace the Authorization request header with "DUMMY" in cassettes
        "filter_headers": [('authorization', 'DUMMY')],
    }


@pytest.fixture
def test_user(tmp_path):
    return maintain_kubeusers.User("blurp", 502, tmp_path)
