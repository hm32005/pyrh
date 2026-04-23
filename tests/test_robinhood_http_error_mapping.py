# coding=utf-8
"""HTTP status-code → exception mapping for Robinhood quote / fundamentals paths.

Issue #79 (investment-system-docs): previously, *any* ``requests.HTTPError``
raised inside ``quote_data`` / ``quotes_data`` / ``get_quote_list`` / ``fundamentals``
was translated to ``InvalidTickerSymbol``. When the Robinhood backend was down
(5xx) or rate-limiting the caller (429), users were told "invalid ticker" —
wasting debugging time on the wrong root cause.

These tests pin the status-code dispatch:

* 5xx             → ``RobinhoodServerError``   (outage; retry later)
* 429             → ``RobinhoodRateLimitError`` (back off; respect Retry-After)
* 4xx (404, etc.) → ``InvalidTickerSymbol``    (unchanged behaviour)
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
# quote_data
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_quote_data_5xx_raises_server_error_not_invalid_ticker(status):
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.quote_data("TSLA")

    # Must NOT be an InvalidTickerSymbol (the bug being fixed).
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    # Message should mention the status so callers / logs can diagnose.
    assert str(status) in str(exc_info.value)


def test_quote_data_404_still_raises_invalid_ticker():
    """Regression guard: truly-bad tickers must keep mapping to InvalidTickerSymbol."""
    from pyrh.exceptions import InvalidTickerSymbol

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidTickerSymbol):
            rh.quote_data("NOSUCHTICKER")


def test_quote_data_429_raises_rate_limit_error_with_retry_after():
    """429 is 4xx but semantically distinct — don't tell the user to fix their input."""
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": "42"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    # Retry-After surfaced as an attribute for programmatic backoff.
    assert getattr(exc_info.value, "retry_after", None) == 42


def test_quote_data_429_without_retry_after_header():
    """429 without Retry-After: still a rate-limit error, retry_after is None."""
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


def test_quote_data_http_error_without_response_raises_invalid_ticker():
    """Defensive: if HTTPError has no .response (rare), preserve old behaviour."""
    from pyrh.exceptions import InvalidTickerSymbol

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise requests.exceptions.HTTPError("boom — no response attached")

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidTickerSymbol):
            rh.quote_data("TSLA")


# ---------------------------------------------------------------------------
# quotes_data (batched)
# ---------------------------------------------------------------------------


def test_quotes_data_5xx_raises_server_error():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(503)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError):
            rh.quotes_data(["TSLA", "AAPL"])


def test_quotes_data_404_still_raises_invalid_ticker():
    from pyrh.exceptions import InvalidTickerSymbol

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidTickerSymbol):
            rh.quotes_data(["NOPE"])


def test_quotes_data_429_raises_rate_limit():
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": "5"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quotes_data(["TSLA"])

    assert exc_info.value.retry_after == 5


# ---------------------------------------------------------------------------
# fundamentals (same except 4 raise site, different URL path)
# ---------------------------------------------------------------------------


def test_fundamentals_5xx_raises_server_error():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(502)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError):
            rh.fundamentals("TSLA")


def test_fundamentals_404_still_raises_invalid_ticker():
    from pyrh.exceptions import InvalidTickerSymbol

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidTickerSymbol):
            rh.fundamentals("NOPE")


# ---------------------------------------------------------------------------
# Exception hierarchy — new classes inherit from PyrhException so that
# existing ``except PyrhException`` catch-alls continue to work.
# ---------------------------------------------------------------------------


def test_new_exceptions_inherit_from_pyrh_exception():
    from pyrh.exceptions import (
        PyrhException,
        RobinhoodRateLimitError,
        RobinhoodServerError,
    )

    assert issubclass(RobinhoodServerError, PyrhException)
    assert issubclass(RobinhoodRateLimitError, PyrhException)
