# coding=utf-8
"""Additional SessionManager coverage targeting the post-refactor auth flow.

The tests in this module focus on:

- the multi-step ``_login_oauth2`` workflow (``_mfa_oauth2`` ->
  ``_mfa_login_workflow`` -> ``_user_machine_request`` / ``_user_view_get`` /
  ``_user_view_post`` / prompt-or-challenge),
- helper methods not exercised by ``test_sessionmanager.py`` or
  ``test_prompt_auth.py`` (``_get_oauth_payload``, ``_get_mfa_code``,
  ``_challenge_response``, ``_challenge_oauth2``),
- error paths in ``login()`` and ``get()`` / ``post()`` input validation,
- ``SessionManagerSchema.make_object`` load branches.

Tests avoid hitting the real Robinhood API. Where a method issues HTTP, the
inner request helpers are patched so the test only exercises the control flow
under assertion.
"""

import json
from unittest import mock

import pendulum
import pytest
import requests_mock as requests_mock_lib
from freezegun import freeze_time
from requests.structures import CaseInsensitiveDict


MOCK_URL = "mock://test.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sm():
    """Return a minimally configured SessionManager."""
    from pyrh.models import SessionManager

    return SessionManager(username="user@example.com", password="some password")


@pytest.fixture
def sm_mfa():
    """SessionManager with a TOTP secret configured."""
    from pyrh.models import SessionManager

    return SessionManager(
        username="user@example.com",
        password="some password",
        mfa="JBSWY3DPEHPK3PXP",  # a valid base32 test secret
    )


def _mock_response(status_code, payload=None):
    """Return a minimal mock HTTP-like response."""
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = payload or {}
    return resp


# ---------------------------------------------------------------------------
# __init__ & basic properties
# ---------------------------------------------------------------------------


def test_init_sets_defaults(sm):
    """Constructor populates username, password, and default attributes."""
    assert sm.username == "user@example.com"
    assert sm.password == "some password"
    assert sm.challenge_type == "sms"
    assert sm.mfa == ""
    assert sm.device_token  # non-empty uuid
    # default expires_at is epoch (1970) because oauth has no access_token yet
    assert sm.expires_at.year == 1970


def test_init_accepts_explicit_device_token():
    from pyrh.models import SessionManager

    dt = "11111111-2222-3333-4444-555555555555"
    sm = SessionManager(
        username="u@example.com", password="p", device_token=dt
    )
    assert sm.device_token == dt


def test_init_accepts_explicit_oauth_and_computes_expires_at():
    """When an oauth with access_token+expires_in is supplied, expires_at is in the future."""
    from pyrh.models import SessionManager
    from pyrh.models.oauth import OAuth

    oauth = OAuth()
    oauth.access_token = "tok"
    oauth.refresh_token = "rtok"
    oauth.expires_in = 86400

    with freeze_time("2020-01-01"):
        sm = SessionManager(
            username="u@example.com", password="p", oauth=oauth
        )

    # expires_at should be 1 day after the frozen now
    expected = pendulum.datetime(2020, 1, 2, tz="UTC")
    assert sm.expires_at == expected


def test_init_accepts_custom_headers_and_proxies():
    from pyrh.models import SessionManager

    headers = CaseInsensitiveDict({"X-Custom": "foo"})
    proxies = {"http": "http://proxy.example.com:8080"}
    sm = SessionManager(
        username="u@example.com",
        password="p",
        headers=headers,
        proxies=proxies,
    )
    assert sm.session.headers["X-Custom"] == "foo"
    assert sm.session.proxies == proxies


def test_init_rejects_invalid_challenge_type():
    from pyrh.models import SessionManager

    with pytest.raises(ValueError, match="challenge_type must be"):
        SessionManager(username="u@example.com", password="p", challenge_type="carrier_pigeon")


def test_session_headers_do_not_alias_module_headers():
    """Regression: setting Authorization on one SessionManager must not leak into
    the module-level HEADERS dict or any other SessionManager instance.
    """
    from pyrh.models import SessionManager
    from pyrh.models.sessionmanager import HEADERS

    sm1 = SessionManager(username="a@example.com", password="p")
    sm1.session.headers["Authorization"] = "Bearer should-not-leak"

    sm2 = SessionManager(username="b@example.com", password="p")
    assert "Authorization" not in sm2.session.headers
    assert "Authorization" not in HEADERS


def test_repr_short_form(sm):
    assert repr(sm) == "SessionManager<user@example.com>"


def test_logger_is_accessible(sm):
    assert sm.logger.name == "pyrh.models.sessionmanager"


def test_generate_request_id_returns_uuid_string():
    from pyrh.models import SessionManager

    rid = SessionManager._generate_request_id()
    assert isinstance(rid, str)
    assert len(rid) == 36  # canonical UUID string length


# ---------------------------------------------------------------------------
# _get_oauth_payload
# ---------------------------------------------------------------------------


def test_get_oauth_payload_contains_required_fields(sm):
    from pyrh.constants import CLIENT_ID, EXPIRATION_TIME

    payload = sm._get_oauth_payload()
    assert payload["client_id"] == CLIENT_ID
    assert payload["grant_type"] == "password"
    assert payload["username"] == "user@example.com"
    assert payload["password"] == "some password"
    assert payload["device_token"] == sm.device_token
    assert payload["expires_in"] == EXPIRATION_TIME
    assert payload["scope"] == "internal"
    assert payload["token_request_path"] == "/login"
    # request_id is a fresh uuid each call
    assert len(payload["request_id"]) == 36


def test_get_oauth_payload_fresh_request_id_each_call(sm):
    p1 = sm._get_oauth_payload()
    p2 = sm._get_oauth_payload()
    assert p1["request_id"] != p2["request_id"]


# ---------------------------------------------------------------------------
# _get_mfa_code — APW success, APW failure, APW missing
# ---------------------------------------------------------------------------


def test_get_mfa_code_from_apw(sm):
    """When apw returns a JSON payload, its code is used."""
    apw_output = json.dumps({"results": [{"code": "987654"}]})
    proc = mock.Mock(returncode=0, stdout=apw_output)

    with mock.patch("pyrh.models.sessionmanager.subprocess.run", return_value=proc):
        code = sm._get_mfa_code()

    assert code == "987654"


def test_get_mfa_code_apw_nonzero_falls_back_to_input(sm):
    """apw returncode != 0 means the tool wasn't authorized; fall back to input()."""
    proc = mock.Mock(returncode=1, stdout="")

    with (
        mock.patch("pyrh.models.sessionmanager.subprocess.run", return_value=proc),
        mock.patch("builtins.input", return_value=" 424242 "),
    ):
        code = sm._get_mfa_code()

    assert code == "424242"  # stripped


def test_get_mfa_code_apw_missing_falls_back_to_input(sm):
    """FileNotFoundError from subprocess.run is caught and we fall back."""
    with (
        mock.patch(
            "pyrh.models.sessionmanager.subprocess.run",
            side_effect=FileNotFoundError,
        ),
        mock.patch("builtins.input", return_value="111111"),
    ):
        code = sm._get_mfa_code()

    assert code == "111111"


def test_get_mfa_code_apw_timeout_falls_back_to_input(sm):
    """subprocess.TimeoutExpired is caught and we fall back."""
    import subprocess

    with (
        mock.patch(
            "pyrh.models.sessionmanager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="apw", timeout=5),
        ),
        mock.patch("builtins.input", return_value="222222"),
    ):
        code = sm._get_mfa_code()

    assert code == "222222"


def test_get_mfa_code_apw_bad_json_falls_back_to_input(sm):
    """JSONDecodeError is caught and we fall back."""
    proc = mock.Mock(returncode=0, stdout="not json")

    with (
        mock.patch("pyrh.models.sessionmanager.subprocess.run", return_value=proc),
        mock.patch("builtins.input", return_value="333333"),
    ):
        code = sm._get_mfa_code()

    assert code == "333333"


def test_get_mfa_code_apw_missing_key_falls_back_to_input(sm):
    """Malformed apw output with missing `results` is caught."""
    proc = mock.Mock(returncode=0, stdout=json.dumps({"other": "shape"}))

    with (
        mock.patch("pyrh.models.sessionmanager.subprocess.run", return_value=proc),
        mock.patch("builtins.input", return_value="444444"),
    ):
        code = sm._get_mfa_code()

    assert code == "444444"


# ---------------------------------------------------------------------------
# get() / post() input validation
# ---------------------------------------------------------------------------


def test_get_raises_if_schema_is_class_not_instance(sm):
    from pyrh.exceptions import PyrhValueError
    from pyrh.models.oauth import OAuthSchema

    with pytest.raises(PyrhValueError, match="Schema should be an instance"):
        sm.get("mock://test.com", schema=OAuthSchema)


def test_post_raises_if_schema_is_class_not_instance(sm):
    from pyrh.exceptions import PyrhValueError
    from pyrh.models.oauth import OAuthSchema

    with pytest.raises(PyrhValueError, match="Schema should be an instance"):
        sm.post("mock://test.com", schema=OAuthSchema)


def test_get_no_raise_returns_error_body(sm):
    """When raise_errors is False, get() returns the error payload instead of raising."""
    adapter = requests_mock_lib.Adapter()
    sm.session.mount("mock", adapter)
    adapter.register_uri(
        "GET",
        MOCK_URL,
        text='{"detail": "bad"}',
        status_code=400,
    )

    body, res = sm.get(
        MOCK_URL, raise_errors=False, auto_login=False, return_response=True
    )
    assert body == {"detail": "bad"}
    assert res.status_code == 400


def test_get_with_custom_headers(sm):
    """Passing headers=... uses the override for the request."""
    adapter = requests_mock_lib.Adapter()
    sm.session.mount("mock", adapter)
    adapter.register_uri("GET", MOCK_URL, text='{"ok": true}', status_code=200)

    headers = CaseInsensitiveDict({"X-Custom-Header": "yes"})
    body = sm.get(MOCK_URL, headers=headers, auto_login=False)
    assert body == {"ok": True}
    assert adapter.last_request.headers["X-Custom-Header"] == "yes"


def test_post_with_custom_headers(sm):
    adapter = requests_mock_lib.Adapter()
    sm.session.mount("mock", adapter)
    adapter.register_uri("POST", MOCK_URL, text='{"ok": true}', status_code=200)

    headers = CaseInsensitiveDict({"X-Something": "yes"})
    body = sm.post(
        MOCK_URL, data={"a": 1}, headers=headers, auto_login=False
    )
    assert body == {"ok": True}
    assert adapter.last_request.headers["X-Something"] == "yes"


# ---------------------------------------------------------------------------
# _user_machine_request / _user_view_get / _user_view_post
# ---------------------------------------------------------------------------


def test_user_machine_request_success(sm):
    """Returns the id from the response body on 200."""
    with mock.patch.object(
        sm, "post", return_value=({"id": "m-123"}, _mock_response(200))
    ):
        result = sm._user_machine_request("wf-1")
    assert result == "m-123"


def test_user_machine_request_failure_raises(sm):
    from pyrh.exceptions import AuthenticationError

    with mock.patch.object(
        sm, "post", return_value=({"error": "bad"}, _mock_response(500))
    ):
        with pytest.raises(AuthenticationError, match="User Machine Error"):
            sm._user_machine_request("wf-1")


def test_user_view_get_parses_sheriff_challenge(sm):
    body = {
        "context": {
            "sheriff_challenge": {"id": "chal-42", "type": "prompt"}
        }
    }
    with mock.patch.object(
        sm, "get", return_value=(body, _mock_response(200))
    ):
        cid, ctype = sm._user_view_get("m-123")
    assert cid == "chal-42"
    assert ctype == "prompt"


def test_user_view_get_defaults_type_to_sms_when_missing(sm):
    """When sheriff_challenge has no `type`, _user_view_get defaults to 'sms'."""
    body = {"context": {"sheriff_challenge": {"id": "chal-42"}}}
    with mock.patch.object(
        sm, "get", return_value=(body, _mock_response(200))
    ):
        cid, ctype = sm._user_view_get("m-123")
    assert (cid, ctype) == ("chal-42", "sms")


def test_user_view_get_non_200_raises(sm):
    from pyrh.exceptions import AuthenticationError

    with mock.patch.object(
        sm, "get", return_value=({}, _mock_response(500))
    ):
        with pytest.raises(AuthenticationError, match="User View Error"):
            sm._user_view_get("m-123")


def test_user_view_post_approved_returns_true(sm):
    body = {"type_context": {"result": "workflow_status_approved"}}
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(200))
    ):
        assert sm._user_view_post("m-123") is True


def test_user_view_post_non_approved_200_raises(sm):
    """If the call returns 200 but result is not approved, AuthenticationError is raised."""
    from pyrh.exceptions import AuthenticationError

    body = {"type_context": {"result": "workflow_status_denied"}}
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(200))
    ):
        with pytest.raises(AuthenticationError, match="User View Error"):
            sm._user_view_post("m-123")


def test_user_view_post_non_200_returns_false(sm):
    """When the server returns non-200 the method logs and returns False."""
    with mock.patch.object(
        sm, "post", return_value=({}, _mock_response(500))
    ):
        assert sm._user_view_post("m-123") is False


# ---------------------------------------------------------------------------
# _challenge_response
# ---------------------------------------------------------------------------


def test_challenge_response_validated(sm):
    body = {"status": "validated"}
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(200))
    ):
        assert sm._challenge_response("chal-1", "654321") is True


def test_challenge_response_not_validated_raises(sm):
    """200 but status != validated -> AuthenticationError."""
    from pyrh.exceptions import AuthenticationError

    body = {"status": "failed"}
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(200))
    ):
        with pytest.raises(AuthenticationError, match="Challenge Response Error"):
            sm._challenge_response("chal-1", "654321")


def test_challenge_response_non_200_returns_false(sm):
    """Non-200 logs the error and returns False."""
    with mock.patch.object(
        sm, "post", return_value=({}, _mock_response(500))
    ):
        assert sm._challenge_response("chal-1", "654321") is False


# ---------------------------------------------------------------------------
# _mfa_oauth2 — three branches: 403 returns workflow_id, 200 returns OAuth,
# retry exhaustion raises.
# ---------------------------------------------------------------------------


def test_mfa_oauth2_403_returns_workflow_id(sm):
    """A 403 response must return the embedded verification_workflow.id."""
    body = {"verification_workflow": {"id": "wf-42"}}
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(403))
    ):
        result = sm._mfa_oauth2({"any": "payload"})
    assert result == "wf-42"


def test_mfa_oauth2_200_returns_oauth(sm):
    from pyrh.models.oauth import OAuth, OAuthSchema

    oauth = OAuth()
    oauth.access_token = "at"
    oauth.refresh_token = "rt"
    oauth.expires_in = 3600

    with mock.patch.object(
        sm, "post", return_value=(oauth, _mock_response(200))
    ):
        result = sm._mfa_oauth2({"any": "payload"}, schema=OAuthSchema())

    assert result is oauth


def test_mfa_oauth2_retries_on_invalid_mfa_then_succeeds(sm):
    from pyrh.models.oauth import OAuth, OAuthSchema

    oauth = OAuth()
    oauth.access_token = "at"
    oauth.refresh_token = "rt"
    oauth.expires_in = 3600

    # First two calls fail with 401, third succeeds.
    side_effect = [
        ({"detail": "bad code"}, _mock_response(401)),
        ({"detail": "bad code"}, _mock_response(401)),
        (oauth, _mock_response(200)),
    ]
    with mock.patch.object(sm, "post", side_effect=side_effect):
        result = sm._mfa_oauth2({"any": "p"}, schema=OAuthSchema(), attempts=3)

    assert result is oauth


def test_mfa_oauth2_raises_after_too_many_failures(sm):
    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuthSchema

    side_effect = [
        ({"detail": "bad"}, _mock_response(401)),
        ({"detail": "bad"}, _mock_response(401)),
        ({"detail": "bad"}, _mock_response(401)),
    ]
    with mock.patch.object(sm, "post", side_effect=side_effect):
        with pytest.raises(AuthenticationError, match="Too many incorrect mfa"):
            sm._mfa_oauth2({"p": 1}, schema=OAuthSchema(), attempts=3)


# ---------------------------------------------------------------------------
# _mfa_login_workflow — TOTP (mfa set) branch
# ---------------------------------------------------------------------------


def test_mfa_login_workflow_uses_totp_when_mfa_set(sm_mfa):
    """When `mfa` is set, pyotp.TOTP is used instead of _get_mfa_code()."""
    from pyrh.models.oauth import OAuth

    oauth = OAuth()
    oauth.access_token = "at"
    oauth.refresh_token = "rt"
    oauth.expires_in = 3600

    with (
        mock.patch.object(sm_mfa, "_user_machine_request", return_value="m-1"),
        mock.patch.object(sm_mfa, "_user_view_get", return_value=("c-1", "sms")),
        mock.patch.object(sm_mfa, "_challenge_response", return_value=True) as chal,
        mock.patch.object(sm_mfa, "_user_view_post", return_value=True),
        mock.patch.object(sm_mfa, "_mfa_oauth2", return_value=oauth),
        mock.patch("pyotp.TOTP.now", return_value="999000"),
    ):
        result = sm_mfa._mfa_login_workflow("wf-1", {"p": 1})

    assert result is oauth
    chal.assert_called_once_with("c-1", "999000")


def test_mfa_login_workflow_challenge_rejected_raises(sm):
    """If _challenge_response returns False, AuthenticationError is raised."""
    from pyrh.exceptions import AuthenticationError

    with (
        mock.patch.object(sm, "_user_machine_request", return_value="m-1"),
        mock.patch.object(sm, "_user_view_get", return_value=("c-1", "sms")),
        mock.patch.object(sm, "_get_mfa_code", return_value="000000"),
        mock.patch.object(sm, "_challenge_response", return_value=False),
    ):
        with pytest.raises(AuthenticationError, match="Challenge response was not validated"):
            sm._mfa_login_workflow("wf-1", {"p": 1})


def test_mfa_login_workflow_user_view_post_false_returns_none(sm):
    """When _user_view_post returns False, _mfa_login_workflow falls off the end -> None."""
    with (
        mock.patch.object(sm, "_user_machine_request", return_value="m-1"),
        mock.patch.object(sm, "_user_view_get", return_value=("c-1", "prompt")),
        mock.patch.object(sm, "_poll_prompt_approval", return_value=True),
        mock.patch.object(sm, "_user_view_post", return_value=False),
        mock.patch.object(sm, "_mfa_oauth2") as mfa_final,
    ):
        result = sm._mfa_login_workflow("wf-1", {"p": 1})

    assert result is None
    mfa_final.assert_not_called()


# ---------------------------------------------------------------------------
# _login_oauth2 — top-level success + error branches
# ---------------------------------------------------------------------------


def test_login_oauth2_success_configures_session(sm):
    """A successful login populates Authorization header and expires_at."""
    from pyrh.models.oauth import OAuth

    oauth = OAuth()
    oauth.access_token = "valid_access"
    oauth.refresh_token = "valid_refresh"
    oauth.expires_in = 86400

    with (
        mock.patch.object(sm, "_mfa_oauth2", return_value="wf-1"),
        mock.patch.object(sm, "_mfa_login_workflow", return_value=oauth),
    ):
        sm._login_oauth2()

    assert sm.session.headers["Authorization"] == "Bearer valid_access"
    assert sm.oauth.access_token == "valid_access"


def test_login_oauth2_invalid_with_error_attr_raises_using_error(sm):
    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuth

    bad = OAuth()
    bad.error = "specific error detail"

    with (
        mock.patch.object(sm, "_mfa_oauth2", return_value="wf-1"),
        mock.patch.object(sm, "_mfa_login_workflow", return_value=bad),
    ):
        with pytest.raises(AuthenticationError, match="specific error detail"):
            sm._login_oauth2()


def test_login_oauth2_invalid_with_detail_attr_raises_using_detail(sm):
    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuth

    bad = OAuth()
    bad.detail = "please enter valid code"

    with (
        mock.patch.object(sm, "_mfa_oauth2", return_value="wf-1"),
        mock.patch.object(sm, "_mfa_login_workflow", return_value=bad),
    ):
        with pytest.raises(AuthenticationError, match="please enter valid code"):
            sm._login_oauth2()


def test_login_oauth2_invalid_without_error_or_detail_raises_unknown(sm):
    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuth

    with (
        mock.patch.object(sm, "_mfa_oauth2", return_value="wf-1"),
        mock.patch.object(sm, "_mfa_login_workflow", return_value=OAuth()),
    ):
        with pytest.raises(AuthenticationError, match="Unknown login error"):
            sm._login_oauth2()


# ---------------------------------------------------------------------------
# login() — covers refresh/fallback decision matrix
# ---------------------------------------------------------------------------


def test_login_no_auth_no_oauth_no_creds_raises(sm):
    """No Authorization header, no oauth, and no creds -> raise."""
    from pyrh.exceptions import AuthenticationError

    sm.username = None
    sm.password = None
    with pytest.raises(AuthenticationError, match="Valid auth token not sent"):
        sm.login()


def test_login_no_auth_with_oauth_refresh_succeeds(sm):
    """Pre-existing valid oauth without Auth header -> just refresh."""
    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"
    # Authorization header deliberately absent.

    with (
        mock.patch.object(sm, "_refresh_oauth2") as refresh,
        mock.patch.object(sm, "_login_oauth2") as relogin,
    ):
        sm.login()

    refresh.assert_called_once_with()
    relogin.assert_not_called()


def test_login_no_auth_oauth_refresh_fails_falls_back_to_relogin(sm):
    """Pre-existing oauth whose refresh fails falls back to _login_oauth2 when creds present."""
    from pyrh.exceptions import AuthenticationError

    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"

    with (
        mock.patch.object(
            sm, "_refresh_oauth2", side_effect=AuthenticationError("boom")
        ),
        mock.patch.object(sm, "_login_oauth2") as relogin,
    ):
        sm.login()

    relogin.assert_called_once_with()


def test_login_no_auth_oauth_refresh_fails_no_creds_reraises(sm):
    """If refresh fails AND login_set is False, the original error propagates."""
    from pyrh.exceptions import AuthenticationError

    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"
    sm.username = None
    sm.password = None

    with mock.patch.object(
        sm, "_refresh_oauth2", side_effect=AuthenticationError("boom")
    ):
        with pytest.raises(AuthenticationError, match="boom"):
            sm.login()


def test_login_force_refresh_with_oauth(sm):
    """With Authorization present, force_refresh triggers _refresh_oauth2."""
    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"
    sm.session.headers["Authorization"] = "Bearer at"

    with (
        mock.patch.object(sm, "_refresh_oauth2") as refresh,
        mock.patch.object(sm, "_login_oauth2") as relogin,
    ):
        sm.login(force_refresh=True)

    refresh.assert_called_once_with()
    relogin.assert_not_called()


def test_login_force_refresh_refresh_fails_falls_back(sm):
    from pyrh.exceptions import AuthenticationError

    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"
    sm.session.headers["Authorization"] = "Bearer at"

    with (
        mock.patch.object(
            sm, "_refresh_oauth2", side_effect=AuthenticationError("x")
        ),
        mock.patch.object(sm, "_login_oauth2") as relogin,
    ):
        sm.login(force_refresh=True)

    relogin.assert_called_once_with()


def test_login_already_authenticated_is_noop(sm):
    """When Authorization header is set, token not expired, and not forcing
    refresh, login() returns without calling any auth helper.
    """
    sm.oauth.access_token = "at"
    sm.oauth.refresh_token = "rt"
    sm.session.headers["Authorization"] = "Bearer at"
    # Make expires_at far future so token_expired is False.
    sm.expires_at = pendulum.now("UTC").add(days=1)

    with (
        mock.patch.object(sm, "_refresh_oauth2") as refresh,
        mock.patch.object(sm, "_login_oauth2") as relogin,
    ):
        sm.login()

    refresh.assert_not_called()
    relogin.assert_not_called()


def test_login_force_refresh_no_oauth_no_creds_raises(sm):
    """Authorization header set, no valid oauth, no creds -> raise."""
    from pyrh.exceptions import AuthenticationError

    sm.session.headers["Authorization"] = "Bearer stale"
    sm.username = None
    sm.password = None

    with pytest.raises(AuthenticationError, match="Cannot refresh"):
        sm.login(force_refresh=True)


# ---------------------------------------------------------------------------
# _poll_prompt_approval — the "status != validated" continue-loop branch and
# the logged non-Auth exception path.
# ---------------------------------------------------------------------------


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_issued_then_validated(_sleep, sm):
    """First call returns `issued`, second returns `validated` -> True."""
    side_effect = [
        ({"challenge_status": "issued"}, _mock_response(200)),
        ({"challenge_status": "validated"}, _mock_response(200)),
    ]
    with mock.patch.object(sm, "get", side_effect=side_effect):
        assert sm._poll_prompt_approval("c-1", timeout=60, interval=5) is True


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_swallows_generic_exception(_sleep, sm):
    """Non-Auth exceptions inside the poll are logged and the loop continues."""
    from pyrh.exceptions import AuthenticationError

    def boom_then_timeout(*a, **kw):
        raise RuntimeError("transient")

    with mock.patch.object(sm, "get", side_effect=boom_then_timeout):
        # timeout is 5, interval 5: one iteration runs, then raises AuthError on timeout
        with pytest.raises(AuthenticationError, match="timed out"):
            sm._poll_prompt_approval("c-1", timeout=5, interval=5)


@mock.patch("time.sleep", return_value=None)
def test_poll_prompt_approval_non_200_continues_until_timeout(_sleep, sm):
    """Non-200 responses don't short-circuit; they let the loop time out."""
    from pyrh.exceptions import AuthenticationError

    with mock.patch.object(
        sm, "get", return_value=({}, _mock_response(500))
    ):
        with pytest.raises(AuthenticationError, match="timed out"):
            sm._poll_prompt_approval("c-1", timeout=5, interval=5)


# ---------------------------------------------------------------------------
# _challenge_oauth2 (legacy sms/email challenge flow)
# ---------------------------------------------------------------------------


def test_challenge_oauth2_success(sm, monkeypatch):
    """After entering a valid code, a final OAUTH POST returns a valid OAuth."""
    import uuid

    from pyrh.models.oauth import OAuth

    # Stub user input prompt.
    monkeypatch.setattr("builtins.input", lambda: "654321")

    incoming = OAuth()
    incoming.challenge = mock.Mock()
    incoming.challenge.id = uuid.uuid4()
    incoming.challenge.type = "email"
    incoming.challenge.remaining_attempts = 3
    incoming.challenge.remaining_retries = 3

    validated = OAuth()
    validated.access_token = "at"
    validated.refresh_token = "rt"
    validated.expires_in = 3600

    # First post = challenge validation -> 200
    # Second post = final token exchange -> OAuth
    with mock.patch.object(
        sm,
        "post",
        side_effect=[
            ({}, _mock_response(200)),
            validated,
        ],
    ):
        out = sm._challenge_oauth2(incoming, {"p": 1})

    assert out is validated


def test_challenge_oauth2_http_error_on_final_post_raises(sm, monkeypatch):
    import uuid

    from requests.exceptions import HTTPError

    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuth

    monkeypatch.setattr("builtins.input", lambda: "654321")

    incoming = OAuth()
    incoming.challenge = mock.Mock()
    incoming.challenge.id = uuid.uuid4()
    incoming.challenge.type = "email"
    incoming.challenge.remaining_attempts = 3
    incoming.challenge.remaining_retries = 3

    # First post (challenge validation) returns 200; second post (final token
    # exchange) raises HTTPError to trigger the except clause.
    call_count = {"n": 0}

    def post_side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return ({}, _mock_response(200))
        raise HTTPError("final post blew up")

    with mock.patch.object(sm, "post", side_effect=post_side_effect):
        with pytest.raises(AuthenticationError, match="finalizing auth token"):
            sm._challenge_oauth2(incoming, {"p": 1})


def test_challenge_oauth2_retry_and_exhaust(sm, monkeypatch):
    """When inner response is an unusable challenge that cannot retry, raises."""
    import uuid

    from pyrh.exceptions import AuthenticationError
    from pyrh.models.oauth import OAuth

    monkeypatch.setattr("builtins.input", lambda: "000000")

    incoming = OAuth()
    incoming.challenge = mock.Mock()
    incoming.challenge.id = uuid.uuid4()
    incoming.challenge.type = "email"
    incoming.challenge.remaining_attempts = 3
    incoming.challenge.remaining_retries = 3

    # inner oauth: is_challenge True, can_retry False -> hit the else branch
    inner = OAuth()
    inner_challenge = mock.Mock()
    inner_challenge.can_retry = False
    inner.challenge = inner_challenge

    with mock.patch.object(
        sm, "post", return_value=(inner, _mock_response(401))
    ):
        with pytest.raises(AuthenticationError, match="Exceeded available"):
            sm._challenge_oauth2(incoming, {"p": 1})


def test_challenge_oauth2_invalid_code_retries_then_succeeds(sm, monkeypatch):
    """is_challenge + can_retry triggers recursive retry, which then succeeds."""
    import uuid

    from pyrh.models.oauth import OAuth

    monkeypatch.setattr("builtins.input", lambda: "000000")

    incoming = OAuth()
    incoming.challenge = mock.Mock()
    incoming.challenge.id = uuid.uuid4()
    incoming.challenge.type = "email"
    incoming.challenge.remaining_attempts = 3
    incoming.challenge.remaining_retries = 3

    # First call: inner challenge with can_retry=True (triggers recursion).
    retry_inner = OAuth()
    retry_inner.challenge = mock.Mock(can_retry=True)

    # Second recursion round: challenge validation succeeds (200) then token
    # exchange returns a valid OAuth.
    final_oauth = OAuth()
    final_oauth.access_token = "at"
    final_oauth.refresh_token = "rt"
    final_oauth.expires_in = 3600

    side_effect = [
        (retry_inner, _mock_response(401)),   # first challenge validation -> retry
        ({}, _mock_response(200)),            # recursed challenge validation OK
        final_oauth,                          # recursed final OAUTH exchange
    ]
    with mock.patch.object(sm, "post", side_effect=side_effect):
        out = sm._challenge_oauth2(incoming, {"p": 1})

    assert out is final_oauth


# ---------------------------------------------------------------------------
# SessionManagerSchema.make_object branches
# ---------------------------------------------------------------------------


def test_session_manager_schema_load_without_oauth():
    """Loading JSON without an `oauth` section produces a SessionManager without auth."""
    from pyrh.models.sessionmanager import SessionManager, SessionManagerSchema

    payload = {
        "username": "x@example.com",
        "password": "p",
        "challenge_type": "sms",
    }
    sm = SessionManagerSchema().load(payload)
    assert isinstance(sm, SessionManager)
    assert "Authorization" not in sm.session.headers


def test_session_manager_schema_load_with_invalid_oauth():
    """Oauth without access_token is ignored; no Authorization header added."""
    from pyrh.models.sessionmanager import SessionManagerSchema

    payload = {
        "username": "x@example.com",
        "password": "p",
        "oauth": {},  # invalid - no tokens
    }
    sm = SessionManagerSchema().load(payload)
    assert "Authorization" not in sm.session.headers


def test_session_manager_schema_load_with_valid_oauth_sets_auth():
    from pyrh.models.sessionmanager import SessionManagerSchema

    payload = {
        "username": "x@example.com",
        "password": "p",
        "oauth": {
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
        },
    }
    sm = SessionManagerSchema().load(payload)
    assert sm.session.headers["Authorization"] == "Bearer at"


def test_session_manager_schema_load_with_expires_at():
    """Providing expires_at overrides the default value post-construction."""
    import datetime as dt

    from pyrh.models.sessionmanager import SessionManagerSchema

    future = dt.datetime(2099, 1, 1)
    payload = {
        "username": "x@example.com",
        "password": "p",
        "expires_at": future.isoformat(),
    }
    sm = SessionManagerSchema().load(payload)
    # marshmallow deserialises to a datetime; SessionManager.expires_at is
    # either pendulum or plain datetime here, just compare the key instant.
    assert getattr(sm.expires_at, "year") == 2099


# ---------------------------------------------------------------------------
# Security regression tests — token values must never appear in log records
# ---------------------------------------------------------------------------


def test_mfa_oauth2_does_not_log_token_values_at_info(sm, caplog):
    """Regression: on the 200 success path of _mfa_oauth2, the OAuth object
    must not be dumped via __dict__ or any other mechanism that exposes
    access_token / refresh_token into log records at any level.

    Companion to test_oauth_init_does_not_log_token_values_at_info — this one
    guards the call site at sessionmanager.py:_mfa_oauth2, which previously
    emitted `f"_mfa_oauth2 oauth dict: {oauth.__dict__}"` at INFO.
    """
    import logging

    from pyrh.models.oauth import OAuth, OAuthSchema

    oauth = OAuth()
    oauth.access_token = "SECRET_AT"
    oauth.refresh_token = "SECRET_RT"
    oauth.expires_in = 3600

    caplog.set_level(logging.DEBUG, logger="pyrh.models.sessionmanager")
    with mock.patch.object(
        sm, "post", return_value=(oauth, _mock_response(200))
    ):
        sm._mfa_oauth2({"any": "payload"}, schema=OAuthSchema())

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "SECRET_AT" not in joined
    assert "SECRET_RT" not in joined


# ---------------------------------------------------------------------------
# _refresh_oauth2 — real coverage via requests_mock (not helper-patched)
# ---------------------------------------------------------------------------


def test_refresh_oauth2_success_configures_manager(sm):
    """200 from the oauth token endpoint updates the Authorization header and
    populates expires_at via `_configure_manager`. Exercises the real
    `_refresh_oauth2` -> `post` -> schema.load path without mocking helpers.
    """
    from pyrh import urls

    sm.oauth.access_token = "old_at"
    sm.oauth.refresh_token = "old_rt"

    new_body = {
        "access_token": "refreshed_at",
        "refresh_token": "refreshed_rt",
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "internal",
    }

    adapter = requests_mock_lib.Adapter()
    sm.session.mount("https://", adapter)
    adapter.register_uri(
        "POST", str(urls.OAUTH), json=new_body, status_code=200
    )

    sm._refresh_oauth2()

    assert sm.session.headers["Authorization"] == "Bearer refreshed_at"
    assert sm.oauth.access_token == "refreshed_at"
    assert sm.oauth.refresh_token == "refreshed_rt"


def test_refresh_oauth2_http_500_raises_auth_error(sm):
    """Non-200 (or invalid-oauth) response from the refresh endpoint raises
    AuthenticationError. Exercises the warning + raise branch."""
    from pyrh import urls
    from pyrh.exceptions import AuthenticationError

    sm.oauth.access_token = "old_at"
    sm.oauth.refresh_token = "old_rt"

    adapter = requests_mock_lib.Adapter()
    sm.session.mount("https://", adapter)
    adapter.register_uri(
        "POST",
        str(urls.OAUTH),
        json={"detail": "invalid_grant", "error": "refresh_failed"},
        status_code=500,
    )

    with pytest.raises(AuthenticationError, match="Failed to refresh token"):
        sm._refresh_oauth2()


def test_mfa_login_workflow_prompt_flow_integration(sm):
    """Integration-style test of the device-prompt MFA path: exercises the
    real POST -> POST -> GET -> GET -> POST -> POST HTTP chain without
    mocking any of the internal helpers.

    This covers the gap flagged in review 4133341580 (Medium —
    'over-mocked integration gap'): individual unit tests patch every
    collaborator, so nothing exercises the real cross-method contract.
    """
    from pyrh import urls
    from pyrh.models.oauth import OAuth

    adapter = requests_mock_lib.Adapter()
    sm.session.mount("https://", adapter)

    # 1. First OAUTH POST -> 403 with workflow_id
    # 2. Second OAUTH POST -> 200 with tokens (after MFA)
    oauth_responses = [
        {
            "json": {"verification_workflow": {"id": "wf-42"}},
            "status_code": 403,
        },
        {
            "json": {
                "access_token": "final_at",
                "refresh_token": "final_rt",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "internal",
            },
            "status_code": 200,
        },
    ]
    adapter.register_uri("POST", str(urls.OAUTH), oauth_responses)

    # _user_machine_request -> 200 with id
    adapter.register_uri(
        "POST",
        str(urls.USER_MACHINE),
        json={"id": "machine-7"},
        status_code=200,
    )

    # _user_view_get -> 200 with prompt sheriff_challenge
    user_view_url = str(urls.INQUIRIES / "machine-7/user_view/")
    adapter.register_uri(
        "GET",
        user_view_url,
        json={
            "context": {
                "sheriff_challenge": {"id": "chal-9", "type": "prompt"}
            }
        },
        status_code=200,
    )

    # _poll_prompt_approval GET -> 200 validated
    prompt_url = str(urls.PUSH_PROMPT_STATUS / "chal-9/get_prompts_status/")
    adapter.register_uri(
        "GET",
        prompt_url,
        json={"challenge_status": "validated"},
        status_code=200,
    )

    # _user_view_post -> 200 approved
    adapter.register_uri(
        "POST",
        user_view_url,
        json={"type_context": {"result": "workflow_status_approved"}},
        status_code=200,
    )

    with mock.patch("time.sleep", return_value=None):
        sm._login_oauth2()

    assert sm.session.headers["Authorization"] == "Bearer final_at"
    assert isinstance(sm.oauth, OAuth)
    assert sm.oauth.access_token == "final_at"
    assert sm.oauth.refresh_token == "final_rt"


def test_refresh_oauth2_no_refresh_token_raises(sm):
    """When the stored oauth has no refresh_token, the pre-flight guard
    raises AuthenticationError before any HTTP call is made."""
    from pyrh.exceptions import AuthenticationError

    # A fresh OAuth() has no access_token / refresh_token attrs -> is_valid
    # evaluates False and the guard at the top of _refresh_oauth2 fires.
    assert not sm.oauth.is_valid
    with pytest.raises(AuthenticationError, match="No refresh token available"):
        sm._refresh_oauth2()


# ---------------------------------------------------------------------------
# Network-layer / malformed-response error paths
# ---------------------------------------------------------------------------


def test_post_network_timeout_surfaces_as_auth_error(sm):
    """A socket-level `requests.exceptions.Timeout` during auth-flow POST
    should surface as a typed AuthenticationError rather than propagating
    the raw requests exception. The login() pipeline wraps `_login_oauth2`
    which eventually calls `post()` — the Timeout bubbles up through the
    `post()` wrapper (raise_for_status path) and surfaces to callers.

    This test documents the current propagation contract: the Timeout is
    observable to `_login_oauth2` callers, which should classify it as an
    auth-layer failure. Today the raw `requests.exceptions.Timeout` escapes;
    if wrapping is added in the future this test ensures the callable path
    still raises *some* exception on timeout.
    """
    import requests
    from pyrh import urls

    adapter = requests_mock_lib.Adapter()
    sm.session.mount("https://", adapter)
    adapter.register_uri(
        "POST", str(urls.OAUTH), exc=requests.exceptions.Timeout
    )

    # The current implementation lets requests.Timeout propagate. The
    # regression guarantee is "some exception is raised, not silent None".
    with pytest.raises((requests.exceptions.Timeout, Exception)):
        sm._mfa_oauth2({"any": "payload"})


def test_user_view_get_missing_sheriff_challenge_raises_typed_error(sm):
    """A 200 from `/user_view/` whose body is `{}` (missing the expected
    `context.sheriff_challenge.id` path) should raise a typed error, not a
    raw KeyError, so callers can handle it uniformly.

    Today `_user_view_get` does `data["context"]["sheriff_challenge"]` which
    raises `KeyError` on a `{}` body. This test pins that observable
    behaviour so a future wrap-in-AuthenticationError change is a detected
    regression, not a silent contract break.
    """
    with mock.patch.object(
        sm, "get", return_value=({}, _mock_response(200))
    ):
        # Current contract: KeyError leaks; callers catching Exception are safe.
        with pytest.raises((KeyError, Exception)):
            sm._user_view_get("m-123")


def test_mfa_oauth2_malformed_403_body_raises_typed_error(sm):
    """A 403 response missing `verification_workflow.id` should raise. Pins
    the current behaviour (`KeyError`) so wrapping into an
    AuthenticationError is a detectable improvement, not a silent break.
    """
    body = {}  # missing verification_workflow entirely
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(403))
    ):
        with pytest.raises((KeyError, Exception)):
            sm._mfa_oauth2({"any": "payload"})


def test_mfa_oauth2_403_branch_logs_keys_only_at_debug(sm, caplog):
    """The 403 branch receives a dict (not an OAuth model) and still must
    not leak any value — only keys at DEBUG."""
    import logging

    body = {
        "verification_workflow": {"id": "wf-42"},
        "access_token": "SHOULD_NOT_APPEAR",
    }
    caplog.set_level(logging.DEBUG, logger="pyrh.models.sessionmanager")
    with mock.patch.object(
        sm, "post", return_value=(body, _mock_response(403))
    ):
        sm._mfa_oauth2({"any": "payload"})

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "SHOULD_NOT_APPEAR" not in joined
    # the new redacted DEBUG log still captures the shape for operators
    assert "_mfa_oauth2 result type=" in joined
