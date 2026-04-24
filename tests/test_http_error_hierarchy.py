# coding=utf-8
"""Hierarchy tests for HTTP-origin exceptions.

Issue #139: introduce a ``RobinhoodHttpError`` base class so callers can
catch "any HTTP-origin failure" with a single ``except`` clause without
resorting to the too-broad ``except PyrhException`` (which would also
catch config / cache / auth-setup errors unrelated to HTTP).

Issue #140: split the 4xx fallback into ``RobinhoodAuthError`` (401/403)
vs the per-caller resource fallback (``InvalidTickerSymbol`` /
``InvalidOptionId`` / ``RobinhoodResourceError``) so callers can
distinguish auth-token-expired failures (warrant a re-login prompt)
from "resource not found" failures (don't).

Backwards-compatibility invariants pinned here:
* Every HTTP-origin exception remains a ``PyrhException`` — legacy
  ``except PyrhException`` callers keep working.
* ``RobinhoodAuthError`` is a ``RobinhoodHttpError`` — so the new
  single-clause catch works for 401/403 too.
"""
from unittest.mock import patch

import pytest
import requests


def _http_error(status_code, headers=None):
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    return requests.exceptions.HTTPError(response=resp)


def _fresh_robinhood():
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


# ---------------------------------------------------------------------------
# #139 — RobinhoodHttpError base class
# ---------------------------------------------------------------------------


def test_robinhood_http_error_exists_and_subclasses_pyrh_exception():
    """Issue #139: the base class must exist and be a ``PyrhException``."""
    from pyrh.exceptions import PyrhException, RobinhoodHttpError

    assert issubclass(RobinhoodHttpError, PyrhException)


@pytest.mark.parametrize(
    "cls_name",
    [
        "RobinhoodServerError",
        "RobinhoodRateLimitError",
        "RobinhoodResourceError",
        "InvalidTickerSymbol",
        "InvalidOptionId",
    ],
)
def test_existing_http_exceptions_inherit_from_robinhood_http_error(cls_name):
    """Issue #139: all five dispatcher-raised exceptions must inherit from the base."""
    from pyrh import exceptions as exc_mod
    from pyrh.exceptions import RobinhoodHttpError

    cls = getattr(exc_mod, cls_name)
    assert issubclass(cls, RobinhoodHttpError), (
        f"{cls_name} must inherit from RobinhoodHttpError so callers can "
        f"use a single ``except RobinhoodHttpError`` for any HTTP-origin failure."
    )


def test_robinhood_http_error_catches_server_error():
    """Ergonomic invariant: ``except RobinhoodHttpError`` catches 5xx dispatches."""
    from pyrh.exceptions import RobinhoodHttpError, RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(503)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodHttpError) as exc_info:
            rh.quote_data("TSLA")
    # Still the specific class too — BC.
    assert isinstance(exc_info.value, RobinhoodServerError)


def test_robinhood_http_error_catches_rate_limit():
    from pyrh.exceptions import RobinhoodHttpError, RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": "7"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodHttpError) as exc_info:
            rh.quote_data("TSLA")
    assert isinstance(exc_info.value, RobinhoodRateLimitError)


def test_robinhood_http_error_catches_invalid_ticker():
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodHttpError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodHttpError) as exc_info:
            rh.quote_data("NOPE")
    assert isinstance(exc_info.value, InvalidTickerSymbol)


# ---------------------------------------------------------------------------
# #140 — RobinhoodAuthError for 401/403
# ---------------------------------------------------------------------------


def test_robinhood_auth_error_exists_and_is_http_error():
    """Issue #140: the auth-error class exists and inherits from the HTTP base."""
    from pyrh.exceptions import RobinhoodAuthError, RobinhoodHttpError

    assert issubclass(RobinhoodAuthError, RobinhoodHttpError)


@pytest.mark.parametrize("status", [401, 403])
def test_quote_data_401_403_raises_auth_error_not_invalid_ticker(status):
    """Issue #140: 401/403 on a quote path must raise ``RobinhoodAuthError``,
    not ``InvalidTickerSymbol``. The user's ticker is fine — their auth expired.
    """
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodAuthError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodAuthError) as exc_info:
            rh.quote_data("TSLA")

    # Must NOT be InvalidTickerSymbol — that's the bug being fixed.
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    assert str(status) in str(exc_info.value)


@pytest.mark.parametrize("status", [401, 403])
def test_auth_error_raised_even_with_resource_fallback(status):
    """Issue #140: the 401/403 branch must fire for EVERY caller, not just
    quote-endpoints. A 401 on ``user()`` (resource-fallback site) must still
    raise ``RobinhoodAuthError``, not ``RobinhoodResourceError``.
    """
    from pyrh.exceptions import RobinhoodAuthError, RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodAuthError) as exc_info:
            rh.user()

    assert not isinstance(exc_info.value, RobinhoodResourceError)


def test_other_4xx_still_uses_resource_fallback():
    """Regression guard: 404/400/etc. must still raise the per-caller fallback.
    Only 401/403 get the auth treatment.
    """
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError):
            rh.user()


def test_auth_error_message_mentions_relogin_hint():
    """Message should tell the caller what to do (re-login), not silently carry
    just the status code like the resource-error variant.
    """
    from pyrh.exceptions import RobinhoodAuthError

    exc = RobinhoodAuthError(401)
    assert "401" in str(exc)
    # Plain-English hint — lowercase match, flexible on wording.
    assert "re-login" in str(exc).lower() or "reauth" in str(exc).lower()
