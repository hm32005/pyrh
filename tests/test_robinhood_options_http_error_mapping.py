# coding=utf-8
"""HTTP status-code -> exception mapping for Robinhood options-quote path.

Issue #125 (investment-system-docs): previously, *any* ``requests.HTTPError``
raised inside ``get_option_market_data`` was translated to ``InvalidOptionId``.
When the Robinhood backend was down (5xx) or rate-limiting the caller (429),
users were told "invalid option id" -- same class of bug #79 fixed on
quote/fundamentals paths, but on the options code path.

These tests pin the status-code dispatch for the options path:

* 5xx             -> ``RobinhoodServerError``   (outage; retry later)
* 429             -> ``RobinhoodRateLimitError`` (back off; respect Retry-After)
* 4xx (404, etc.) -> ``InvalidOptionId``        (unchanged behaviour)
"""
from unittest.mock import patch

import pytest
import requests


def _http_error(status_code, headers=None):
    """Build a ``requests.HTTPError`` whose ``.response`` has the given status."""
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    err = requests.exceptions.HTTPError(response=resp)
    return err


def _fresh_robinhood():
    """Return a ``Robinhood`` instance bypassing ``__init__`` (no auth)."""
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


# ---------------------------------------------------------------------------
# get_option_market_data
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_option_market_data_5xx_raises_server_error_not_invalid_option(status):
    from pyrh.exceptions import InvalidOptionId, RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.get_option_market_data("0000-option-id")

    # Must NOT be InvalidOptionId (the bug being fixed).
    assert not isinstance(exc_info.value, InvalidOptionId)
    # Message should mention the status so callers / logs can diagnose.
    assert str(status) in str(exc_info.value)


def test_option_market_data_404_still_raises_invalid_option_id():
    """Regression guard: truly-bad option IDs must keep mapping to InvalidOptionId."""
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId):
            rh.get_option_market_data("0000-missing-option-id")


def test_option_market_data_429_raises_rate_limit_error_with_retry_after():
    """429 is 4xx but semantically distinct -- don't tell the user to fix their input."""
    from pyrh.exceptions import InvalidOptionId, RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": "42"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.get_option_market_data("0000-option-id")

    assert not isinstance(exc_info.value, InvalidOptionId)
    # Retry-After surfaced as an attribute for programmatic backoff.
    assert getattr(exc_info.value, "retry_after", None) == 42


def test_option_market_data_429_without_retry_after_header():
    """429 without Retry-After: still a rate-limit error, retry_after is None."""
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.get_option_market_data("0000-option-id")

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


def test_option_market_data_http_error_without_response_raises_invalid_option_id():
    """Defensive: if HTTPError has no .response (rare), preserve old behaviour."""
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise requests.exceptions.HTTPError("boom -- no response attached")

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId):
            rh.get_option_market_data("0000-option-id")
