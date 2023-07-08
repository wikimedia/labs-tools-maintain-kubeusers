import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import time
import pytest
from unittest.mock import patch
from .context import (
    K8sAPI,
    k_config,
    client,
    ApiException,
    process_new_users,
    process_disabled_users,
    process_removed_users,
)


@pytest.fixture()
def api_object(are_we_in_k8s, test_user, test_disabled_user):
    if are_we_in_k8s:
        k_config.load_incluster_config()
    else:
        k_config.load_kube_config(
            config_file=os.path.join(os.path.dirname(__file__), "dummy_config")
        )
    api = K8sAPI()
    yield api
    users = [test_user, test_disabled_user]

    # If we created a namespace, delete it to clean up
    for t_user in users:
        try:
            _ = api.core.delete_namespace(
                "tool-{}".format(t_user.name),
                grace_period_seconds=0,
                propagation_policy="Foreground",
            )
        except ApiException:  # If there was no namespace, we are ok with that.
            pass
        try:
            _ = api.policy.delete_pod_security_policy(
                "tool-{}-psp".format(t_user.name),
                grace_period_seconds=0,
                propagation_policy="Foreground",
            )
        except ApiException:  # If there was no PSP, we are ok with that.
            pass

    # If we created an admin configmap, delete it to clean up
    try:
        _ = api.core.delete_namespaced_config_map(
            "maintain-kubeusers",
            "maintain-kubeusers",
            grace_period_seconds=0,
            propagation_policy="Foreground",
        )
    except ApiException:  # If there was no namespace, we are ok with that.
        pass

    # If recording the cassettes, you need to wait for namespaces deletes
    if are_we_in_k8s:
        time.sleep(10)


@pytest.mark.vcr()
def test_cert_creation(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    cert = api_object.approve_cert(test_user.name)
    cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
    assert isinstance(cert_obj, x509.Certificate)


@pytest.mark.vcr()
def test_tool_user_exists_with_namespace_and_configmap(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    current, _ = api_object.get_current_users()
    assert test_user.name in current["tools"]


@pytest.mark.vcr()
def test_tool_renewal(api_object, test_user):
    api_object.generate_csr(test_user.pk, test_user.name)
    test_user.cert = api_object.approve_cert(test_user.name)
    api_object.add_user_access(test_user)
    # We have to patch the configmap to be expired
    config_map = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=client.V1ObjectMeta(name="maintain-kubeusers"),
        data={
            "status": "user created: {}".format(datetime.utcnow().isoformat()),
            "expires": "2018-08-14T22:31:00",
        },
    )
    api_object.core.patch_namespaced_config_map(
        "maintain-kubeusers", "tool-{}".format(test_user.name), body=config_map
    )
    _, expired = api_object.get_current_users()
    assert test_user.name in expired["tools"]
    api_object.update_expired_ns(test_user)
    _, expired = api_object.get_current_users()
    assert test_user.name not in expired["tools"]


@pytest.mark.vcr()
def test_test_admin_exists_with_configmap(api_object, test_admin):
    api_object.generate_csr(test_admin.pk, test_admin.name, True)
    test_admin.cert = api_object.approve_cert(test_admin.name, True)
    api_object.add_user_access(test_admin)
    current, _ = api_object.get_current_users()
    assert test_admin.name in current["admins"]


@pytest.mark.vcr()
def test_test_admin_removal(api_object, test_admin, test_admin2, vcr_cassette):
    api_object.generate_csr(test_admin.pk, test_admin.name, True)
    test_admin.cert = api_object.approve_cert(test_admin.name, True)
    api_object.add_user_access(test_admin)

    api_object.generate_csr(test_admin2.pk, test_admin2.name, True)
    test_admin2.cert = api_object.approve_cert(test_admin2.name, True)
    api_object.add_user_access(test_admin2)

    current, _ = api_object.get_current_users()
    assert test_admin.name in current["admins"]

    start_pos = vcr_cassette.play_count - 1
    removed_users = process_removed_users(
        {"admin2": test_admin2},
        current["admins"],
        api_object,
        True,
    )

    assert removed_users == 1
    end_pos = vcr_cassette.play_count

    # There should be no 404 during removals in this test
    responses = vcr_cassette.responses
    assert not any(
        [404 == x["status"]["code"] for x in responses[start_pos:end_pos]]
    )

    current, _ = api_object.get_current_users()
    assert test_admin.name not in current["admins"]


@pytest.mark.vcr()
def test_admin_renewal(api_object, test_admin):
    api_object.generate_csr(test_admin.pk, test_admin.name, True)
    test_admin.cert = api_object.approve_cert(test_admin.name, True)
    api_object.add_user_access(test_admin)
    # We have to patch the configmap to be expired
    patch_data = {"data": {test_admin.name: "2018-08-14T22:31:00"}}
    api_object.core.patch_namespaced_config_map(
        "maintain-kubeusers", "maintain-kubeusers", body=patch_data
    )
    _, expired = api_object.get_current_users()
    assert test_admin.name in expired["admins"]
    api_object.update_expired_ns(test_admin)
    _, expired = api_object.get_current_users()
    assert test_admin.name not in expired["admins"]


class MockCertObj:
    """Mock an unexpired cert"""

    def __init__(self):
        self.not_valid_after = datetime(2030, 5, 17)


@pytest.mark.vcr()
def test_process_new_users(
    monkeypatch, api_object, test_user, vcr_cassette
):
    def mock_load_cert(*args, **kwargs):
        return MockCertObj()

    monkeypatch.setattr(x509, "load_pem_x509_certificate", mock_load_cert)

    current, _ = api_object.get_current_users()
    start_pos1 = vcr_cassette.play_count - 1

    with patch("os.chown", autospec=True):
        with patch("os.fchown", autospec=True):
            new_tools = process_new_users(
                {"blurp": test_user},
                current["tools"],
                api_object,
                False,
                False,
            )
    end_pos1 = vcr_cassette.play_count - 1

    # There should be no 409s during creations in this test
    responses = vcr_cassette.responses
    assert not any(
        [409 == x["status"]["code"] for x in responses[start_pos1:end_pos1]]
    )

    assert new_tools == 1
    current, _ = api_object.get_current_users()
    assert "blurp" in current["tools"]


@pytest.mark.vcr()
def test_process_new_and_disabled_users(
    monkeypatch, api_object, test_user, test_disabled_user, vcr_cassette
):
    # No need to test that fake certs load in someone else's library
    def mock_load_cert(*args, **kwargs):
        return MockCertObj()

    monkeypatch.setattr(x509, "load_pem_x509_certificate", mock_load_cert)

    # Add blurp but not blorp
    current, _ = api_object.get_current_users()
    assert current == {"admins": [], "tools": []}

    start_pos1 = vcr_cassette.play_count - 1
    with patch("os.chown", autospec=True):
        with patch("os.fchown", autospec=True):
            new_tools = process_new_users(
                {"blurp": test_user, "blorp": test_disabled_user},
                current["tools"],
                api_object,
                False,
                False,
            )

    end_pos1 = vcr_cassette.play_count - 1
    assert new_tools == 1
    current, _ = api_object.get_current_users()
    assert "blurp" in current["tools"]
    assert "blorp" not in current["tools"]

    # Remove blurp
    start_pos2 = vcr_cassette.play_count - 1
    test_user.pwdAccountLockedTime = "000001010000Z"
    with patch("pathlib.Path.touch", autospec=True):
        disabled_tools = process_disabled_users(
            {"blurp": test_user, "blorp": test_disabled_user},
            current["tools"],
            api_object,
        )
    end_pos2 = vcr_cassette.play_count - 1

    # There should be no 409s during creations in this test
    responses = vcr_cassette.responses
    assert not any(
        [409 == x["status"]["code"] for x in responses[start_pos1:end_pos1]]
    )
    # There should be no 404 during removals in this test
    assert not any(
        [404 == x["status"]["code"] for x in responses[start_pos2:end_pos2]]
    )

    time.sleep(2)

    assert disabled_tools == 1
    current, _ = api_object.get_current_users()
    assert "blurp" not in current["tools"]
    assert "blorp" not in current["tools"]


@pytest.mark.vcr()
def test_remove_disabled_user(
    monkeypatch, api_object, test_user, test_disabled_user, vcr_cassette
):
    def mock_load_cert(*args, **kwargs):
        return MockCertObj()

    monkeypatch.setattr(x509, "load_pem_x509_certificate", mock_load_cert)

    # Add blurp so we can remove it
    current, _ = api_object.get_current_users()
    with patch("os.chown", autospec=True):
        with patch("os.fchown", autospec=True):
            new_tools = process_new_users(
                {"blurp": test_user},
                current["tools"],
                api_object,
                False,
                False,
            )

    assert new_tools == 1
    current, _ = api_object.get_current_users()
    assert "blurp" in current["tools"]

    start_pos1 = vcr_cassette.play_count - 1
    # Confirm that we don't remove users that don't need removing
    disabled_tools = process_disabled_users(
        {"blurp": test_user, "blorp": test_disabled_user},
        current["tools"],
        api_object,
    )
    end_pos1 = vcr_cassette.play_count
    assert disabled_tools == 0

    # Remove blurp
    test_user.pwdAccountLockedTime = "000001010000Z"
    start_pos2 = vcr_cassette.play_count - 1
    with patch("pathlib.Path.touch", autospec=True):
        disabled_tools = process_disabled_users(
            {"blurp": test_user},
            current["tools"],
            api_object,
        )
    end_pos2 = vcr_cassette.play_count
    time.sleep(2)

    assert disabled_tools == 1
    responses = vcr_cassette.responses
    # There should be no 409s during creations in this test
    assert not any(
        [409 == x["status"]["code"] for x in responses[start_pos1:end_pos1]]
    )
    # There should be no 404 during removals in this test
    assert not any(
        [404 == x["status"]["code"] for x in responses[start_pos2:end_pos2]]
    )
    current, _ = api_object.get_current_users()
    assert "blurp" not in current["tools"]
