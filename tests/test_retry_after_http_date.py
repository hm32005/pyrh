# coding=utf-8
"""Retry-After header: HTTP-date form parsing (RFC 7231 §7.1.3).

Issue #124 (investment-system-docs): ``_raise_for_http_error`` previously only
parsed the ``Retry-After`` header as an integer "delta-seconds" form. RFC
7231 §7.1.3 also allows an HTTP-date form — e.g.

    Retry-After: Wed, 21 Oct 2015 07:28:00 GMT

Before this fix, an HTTP-date value silently fell through the
``int(header)`` ``ValueError`` branch and the ``retry_after`` attribute was
set to ``None``. If Robinhood's backend ever emitted the HTTP-date form
(during maintenance windows, for example), callers relying on the backoff
hint would lose the signal.

These tests pin the new behavior:

* HTTP-date in the future → ``retry_after`` is a positive int of seconds
  (the delta from "now" to the target time).
* Malformed HTTP-date       → ``retry_after`` is ``None`` (same as other
  unparseable values — no crash, no silent corruption).
* Integer form              → still works (regression guard for legacy behaviour).
"""
from __future__ import annotations

from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import requests

from pyrh.exceptions import RobinhoodRateLimitError


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
# HTTP-date form
# ---------------------------------------------------------------------------


def test_retry_after_http_date_future_surfaces_positive_seconds():
    """``Retry-After: <HTTP-date>`` in the future must produce ``retry_after``
    as a positive int of seconds (the delta from 'now' to the target).

    Before #124 this silently fell through to ``retry_after=None``.
    """
    # 90 seconds in the future. Use 90 (not 30/60) so the delta comfortably
    # survives sub-second timing jitter in CI — the test asserts the value
    # lands in a narrow window near 90.
    target = datetime.now(timezone.utc) + timedelta(seconds=90)
    http_date = format_datetime(target, usegmt=True)

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": http_date})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    retry_after = exc_info.value.retry_after
    # Must be an int (not None) — the fix's core promise.
    assert isinstance(retry_after, int), (
        f"expected int seconds from HTTP-date, got {retry_after!r}"
    )
    # Must be close to the requested 90s window (allow wide jitter band).
    assert 60 <= retry_after <= 120, (
        f"expected ~90s from HTTP-date, got {retry_after}s"
    )


def test_retry_after_http_date_past_clamps_to_zero():
    """HTTP-date in the past must clamp to ``0`` (no negative backoff)."""
    target = datetime.now(timezone.utc) - timedelta(seconds=120)
    http_date = format_datetime(target, usegmt=True)

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": http_date})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    assert exc_info.value.retry_after == 0


def test_retry_after_malformed_falls_back_to_none():
    """Garbage ``Retry-After`` (neither int nor HTTP-date) keeps legacy
    ``retry_after=None`` fallback. No crash, no silent corruption."""
    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(
            429, headers={"Retry-After": "not-a-date not-a-number"}
        )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    assert exc_info.value.retry_after is None


# ---------------------------------------------------------------------------
# Regression guard: integer form still works
# ---------------------------------------------------------------------------


def test_retry_after_integer_form_still_works():
    """Legacy integer form (``Retry-After: 42``) remains supported."""
    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(429, headers={"Retry-After": "42"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.quote_data("TSLA")

    assert exc_info.value.retry_after == 42
