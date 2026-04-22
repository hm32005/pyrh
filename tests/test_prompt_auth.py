# coding=utf-8
"""Tests for device-approval (prompt) auth flow and token refresh."""

from unittest import mock

import pytest
import requests_mock as requests_mock_lib

MOCK_URL = "mock://test.com"
MOCK_PUSH_URL = "mock://push.test.com"


@pytest.fixture
def sm():
    from pyrh.models import SessionManager

    return SessionManager(username="user@example.com", password="some password")


@pytest.fixture
def sm_with_adapter(sm):
    adapter = requests_mock_lib.Adapter()
    sm.session.mount("mock", adapter)
    return sm, adapter


# ---------------------------------------------------------------------------
# _poll_prompt_approval tests
# ---------------------------------------------------------------------------


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_validated(mock_sleep, sm):
    """Returns True immediately when status is 'validated'."""
    adapter = requests_mock_lib.Adapter()
    sm.session.mount("mock", adapter)

    challenge_id = "abc-123"
    poll_url = f"mock://api.robinhood.com/push/{challenge_id}/get_prompts_status/"

    # We need to patch the url construction.  The simplest approach is to mock
    # sm.get so it returns the expected response directly.
    with mock.patch.object(
        sm,
        "get",
        return_value=({"challenge_status": "validated"}, _make_response(200)),
    ):
        result = sm._poll_prompt_approval(challenge_id, timeout=10, interval=5)

    assert result is True


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_timeout(mock_sleep, sm):
    """Raises AuthenticationError after polling exhausts the timeout."""
    from pyrh.exceptions import AuthenticationError

    challenge_id = "abc-123"

    with mock.patch.object(
        sm,
        "get",
        return_value=({"challenge_status": "issued"}, _make_response(200)),
    ):
        with pytest.raises(AuthenticationError, match="timed out"):
            sm._poll_prompt_approval(challenge_id, timeout=10, interval=5)


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_denied(mock_sleep, sm):
    """Raises AuthenticationError immediately when status is 'denied'."""
    from pyrh.exceptions import AuthenticationError

    challenge_id = "abc-123"

    with mock.patch.object(
        sm,
        "get",
        return_value=({"challenge_status": "denied"}, _make_response(200)),
    ):
        with pytest.raises(AuthenticationError, match="denied"):
            sm._poll_prompt_approval(challenge_id, timeout=60, interval=5)


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_expired(mock_sleep, sm):
    """Raises AuthenticationError immediately when status is 'expired'."""
    from pyrh.exceptions import AuthenticationError

    challenge_id = "abc-123"

    with mock.patch.object(
        sm,
        "get",
        return_value=({"challenge_status": "expired"}, _make_response(200)),
    ):
        with pytest.raises(AuthenticationError, match="expired"):
            sm._poll_prompt_approval(challenge_id, timeout=60, interval=5)


# ---------------------------------------------------------------------------
# _mfa_login_workflow — prompt type
# ---------------------------------------------------------------------------


@mock.patch("time.sleep", return_value=None)
def test_mfa_login_workflow_prompt_type(mock_sleep, sm):
    """When challenge type is 'prompt', _poll_prompt_approval is called instead of
    _challenge_response."""
    machine_id = "machine-xyz"
    challenge_id = "chal-456"

    with (
        mock.patch.object(sm, "_user_machine_request", return_value=machine_id),
        mock.patch.object(sm, "_user_view_get", return_value=(challenge_id, "prompt")),
        mock.patch.object(sm, "_poll_prompt_approval", return_value=True) as mock_poll,
        mock.patch.object(sm, "_user_view_post", return_value=True),
        mock.patch.object(
            sm, "_mfa_oauth2", return_value=_make_valid_oauth()
        ) as mock_mfa,
    ):
        result = sm._mfa_login_workflow("workflow-id", {"some": "payload"})

    mock_poll.assert_called_once_with(challenge_id)
    assert result is not None


def test_mfa_login_workflow_sms_type(sm):
    """When challenge type is 'sms', the code path uses _challenge_response."""
    machine_id = "machine-xyz"
    challenge_id = "chal-789"

    with (
        mock.patch.object(sm, "_user_machine_request", return_value=machine_id),
        mock.patch.object(sm, "_user_view_get", return_value=(challenge_id, "sms")),
        mock.patch.object(sm, "_challenge_response", return_value=True) as mock_chal,
        mock.patch.object(sm, "_user_view_post", return_value=True),
        mock.patch.object(sm, "_mfa_oauth2", return_value=_make_valid_oauth()),
        mock.patch.object(sm, "_get_mfa_code", return_value="123456"),
    ):
        result = sm._mfa_login_workflow("workflow-id", {"some": "payload"})

    mock_chal.assert_called_once_with(challenge_id, "123456")
    assert result is not None


# ---------------------------------------------------------------------------
# _refresh_oauth2 tests
# ---------------------------------------------------------------------------


def test_refresh_oauth2_success(sm):
    """When the refresh endpoint returns 200 with a valid token, session is updated."""
    sm.oauth.access_token = "old_token"
    sm.oauth.refresh_token = "my_refresh_token"

    valid_oauth = _make_valid_oauth()

    with mock.patch.object(
        sm,
        "post",
        return_value=(valid_oauth, _make_response(200)),
    ):
        sm._refresh_oauth2()

    assert sm.oauth.access_token == "new_access_token"


def test_refresh_oauth2_failure_falls_back(sm):
    """When the refresh endpoint returns non-200, AuthenticationError is raised."""
    from pyrh.exceptions import AuthenticationError

    sm.oauth.access_token = "old_token"
    sm.oauth.refresh_token = "my_refresh_token"

    invalid_oauth = _make_invalid_oauth()

    with mock.patch.object(
        sm,
        "post",
        return_value=(invalid_oauth, _make_response(401)),
    ):
        with pytest.raises(AuthenticationError, match="Failed to refresh"):
            sm._refresh_oauth2()


def test_refresh_oauth2_no_refresh_token(sm):
    """When there is no valid refresh token, AuthenticationError is raised immediately."""
    from pyrh.exceptions import AuthenticationError

    # Default OAuth() has no access_token / refresh_token
    with pytest.raises(AuthenticationError, match="No refresh token"):
        sm._refresh_oauth2()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code):
    """Return a minimal mock response with the given status code."""
    resp = mock.Mock()
    resp.status_code = status_code
    return resp


def _make_valid_oauth():
    """Return an OAuth object that satisfies oauth.is_valid == True."""
    from pyrh.models.oauth import OAuth

    oauth = OAuth()
    oauth.access_token = "new_access_token"
    oauth.refresh_token = "new_refresh_token"
    oauth.expires_in = 86400
    return oauth


def _make_invalid_oauth():
    """Return an OAuth object that has no tokens (is_valid == False)."""
    from pyrh.models.oauth import OAuth

    return OAuth()
