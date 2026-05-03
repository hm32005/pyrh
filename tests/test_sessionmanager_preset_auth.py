"""Regression test for the Authorization-header pre-set in SessionManager.__init__.

Without this pre-set, every consumer that loads tokens from disk and
constructs a Robinhood instance triggers a refresh_token rotation on
the first HTTP call (RH returns 401 → auto_login → refresh). RH issues
single-use refresh_tokens, so back-to-back or concurrent consumers
fail with 401 because the first one consumed the rotation.

Setting the Authorization header from the loaded OAuth's access_token
at init time removes the missing-header trigger for valid tokens.
"""
from __future__ import annotations

import pendulum
import pytest

from pyrh.models.oauth import OAuth
from pyrh.robinhood import Robinhood


def _make_valid_oauth(access_token: str = "_TEST_ACCESS_TOKEN_") -> OAuth:
    """Build an OAuth with a non-expired access_token suitable for init."""
    future = pendulum.now("UTC").add(days=10)
    return OAuth(
        access_token=access_token,
        refresh_token="_TEST_REFRESH_TOKEN_",
        expires_at=future,
    )


class TestSessionManagerPresetsAuthHeader:
    """SessionManager.__init__ should set the Authorization header from a
    valid loaded OAuth so the first HTTP request doesn't 401-rotate."""

    def test_authorization_header_set_when_oauth_valid(self) -> None:
        rh = Robinhood(oauth=_make_valid_oauth("token_alpha"))
        assert rh.session.headers.get("Authorization") == "Bearer token_alpha", (
            "Authorization header must be pre-set from a valid OAuth — "
            "without it, the first HTTP request 401s and consumes the "
            "single-use refresh_token unnecessarily."
        )

    def test_authorization_header_absent_when_oauth_missing(self) -> None:
        # No oauth kwarg → SessionManager builds an empty OAuth() internally.
        rh = Robinhood()
        assert "Authorization" not in rh.session.headers, (
            "No Authorization header should be set when no valid OAuth is "
            "loaded — auto_login must drive auth in that path."
        )

    def test_authorization_header_absent_when_oauth_expired(self) -> None:
        past = pendulum.now("UTC").subtract(hours=1)
        expired = OAuth(
            access_token="stale_token",
            refresh_token="stale_refresh",
            expires_at=past,
        )
        rh = Robinhood(oauth=expired)
        assert "Authorization" not in rh.session.headers, (
            "Expired OAuth should NOT pre-set the Authorization header — "
            "let the auto_login refresh path take over so the new tokens "
            "land in the session correctly."
        )

    def test_session_isolation_across_instances(self) -> None:
        # Two SessionManagers must not share the Authorization header
        # — coverage pass 2026-04-17 surfaced this as cross-test leakage.
        rh1 = Robinhood(oauth=_make_valid_oauth("token_one"))
        rh2 = Robinhood(oauth=_make_valid_oauth("token_two"))
        assert rh1.session.headers.get("Authorization") == "Bearer token_one"
        assert rh2.session.headers.get("Authorization") == "Bearer token_two"
        assert rh1.session is not rh2.session


@pytest.mark.parametrize("access_token", ["", None])
def test_authorization_header_absent_when_access_token_falsy(access_token) -> None:
    """An OAuth with falsy access_token shouldn't set the header even if
    expires_at is in the future — defensive guard against malformed
    cached credentials."""
    future = pendulum.now("UTC").add(days=10)
    oauth = OAuth(
        access_token=access_token,
        refresh_token="r",
        expires_at=future,
    )
    rh = Robinhood(oauth=oauth)
    assert "Authorization" not in rh.session.headers
