# coding=utf-8
"""Dispatcher context propagation contract (issue #150).

Problem being fixed: when ``_raise_for_http_error`` raises a fallback exception
(``InvalidTickerSymbol`` / ``InvalidOptionId`` / ``RobinhoodResourceError`` /
``RobinhoodOrderSubmissionError``) or a ``RobinhoodServerError`` /
``RobinhoodRateLimitError``, the resulting exception message carries *no*
resource identifier (order id, ticker, instrument url, tag, option id, etc.).
Callers that log the exception see a bare "Robinhood resource error" with no
way to correlate it to the input that triggered the failure — a debuggability
regression versus the legacy ``raise ValueError("Failed for order_id: " +
order_id + ...)`` pattern.

These tests pin the new behaviour:

* ``context: Mapping[str, Any] | None = None`` kwarg on
  ``_raise_for_http_error``.
* Context dict rendered as ``"key1=val1, key2=val2"`` and embedded in the
  message of whichever exception the dispatcher raises.
* Legacy calls (no context kwarg) produce messages identical to pre-PR
  behaviour — backwards-compatible.
"""

import pytest
import requests

from pyrh.exceptions import (
    InvalidOptionId,
    InvalidTickerSymbol,
    RobinhoodOrderSubmissionError,
    RobinhoodRateLimitError,
    RobinhoodResourceError,
    RobinhoodServerError,
)
from pyrh.robinhood import _raise_for_http_error


def _http_error(status_code, headers=None):
    """Build a ``requests.HTTPError`` whose ``.response`` has the given status."""
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    return requests.exceptions.HTTPError(response=resp)


# ---------------------------------------------------------------------------
# Basic context propagation — 4xx fallback branch
# ---------------------------------------------------------------------------


def test_dispatcher_accepts_context_kwarg_and_includes_in_message():
    """The new context kwarg must propagate into the raised exception message."""
    err = _http_error(404)
    with pytest.raises(RobinhoodResourceError) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=RobinhoodResourceError,
            context={"order_id": "abc-123"},
        )
    assert "order_id=abc-123" in str(exc_info.value)


def test_dispatcher_context_kwarg_invalid_ticker_symbol():
    """Ticker context flows into InvalidTickerSymbol (quote/fundamentals fallback)."""
    err = _http_error(404)
    with pytest.raises(InvalidTickerSymbol) as exc_info:
        _raise_for_http_error(err, context={"ticker": "TSLA"})
    assert "ticker=TSLA" in str(exc_info.value)


def test_dispatcher_context_kwarg_invalid_option_id():
    """Option id context flows into InvalidOptionId (options fallback)."""
    err = _http_error(404)
    with pytest.raises(InvalidOptionId) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=InvalidOptionId,
            context={"option_id": "opt-xyz"},
        )
    assert "option_id=opt-xyz" in str(exc_info.value)


def test_dispatcher_context_kwarg_order_submission_error():
    """Order-id context flows into RobinhoodOrderSubmissionError (cancel/submit)."""
    err = _http_error(400)
    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=RobinhoodOrderSubmissionError,
            context={"order_id": "xyz-456"},
        )
    assert "order_id=xyz-456" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Backwards-compatibility: no context kwarg preserves legacy messages
# ---------------------------------------------------------------------------


def test_dispatcher_no_context_preserves_legacy_invalid_ticker_message():
    """Calling without ``context`` must produce the pre-PR InvalidTickerSymbol message."""
    err = _http_error(404)
    with pytest.raises(InvalidTickerSymbol) as exc_info:
        _raise_for_http_error(err)
    # Legacy call produced an InvalidTickerSymbol with no args -> empty/generic str.
    # The message must NOT contain stray parentheses from an empty context wrapper.
    msg = str(exc_info.value)
    assert "()" not in msg  # no ``(empty context)`` leakage
    # Must not contain any '=' — no fake context rendered.
    assert "=" not in msg


def test_dispatcher_no_context_preserves_legacy_resource_error_message():
    """Phase-A legacy message is preserved when context is omitted."""
    err = _http_error(404)
    with pytest.raises(RobinhoodResourceError) as exc_info:
        _raise_for_http_error(err, fallback_exc=RobinhoodResourceError)
    msg = str(exc_info.value)
    assert "()" not in msg
    assert "=" not in msg


def test_dispatcher_no_context_preserves_legacy_server_error_message():
    """5xx branch without context matches the pre-PR RobinhoodServerError message."""
    err = _http_error(503)
    with pytest.raises(RobinhoodServerError) as exc_info:
        _raise_for_http_error(err)
    msg = str(exc_info.value)
    # Legacy message shape: "Robinhood returned 503 — server error, try again later."
    assert "503" in msg
    assert "server error" in msg
    assert "()" not in msg


def test_dispatcher_no_context_preserves_legacy_rate_limit_message():
    """429 branch without context matches the pre-PR RobinhoodRateLimitError message."""
    err = _http_error(429, headers={"Retry-After": "5"})
    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        _raise_for_http_error(err)
    msg = str(exc_info.value)
    assert "429" in msg
    assert "()" not in msg


# ---------------------------------------------------------------------------
# Multi-field context rendering
# ---------------------------------------------------------------------------


def test_dispatcher_context_kwarg_multi_field():
    """Multiple keys render as ``k1=v1, k2=v2`` in insertion order."""
    err = _http_error(404)
    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=RobinhoodOrderSubmissionError,
            context={"ticker": "AAPL", "side": "buy", "quantity": 10},
        )
    msg = str(exc_info.value)
    assert "ticker=AAPL" in msg
    assert "side=buy" in msg
    assert "quantity=10" in msg


def test_dispatcher_context_kwarg_multi_field_exact_order():
    """Pin dict-insertion-order convention end-to-end.

    Issue #161: the contract is "context rendered in insertion order
    (``k1=v1, k2=v2, ...``)". The existing substring assertions
    (``"ticker=AAPL" in msg``) pass regardless of ordering — a future
    refactor that sorts keys alphabetically or stringifies via
    ``repr(dict)`` would pass them silently, losing the stable shape
    callers rely on for greppable log lines.

    This test pins the exact rendered fragment so silent drift
    (alphabetic sort, ``repr()`` dump, ``json.dumps``) trips a failure.
    """
    err = _http_error(404)
    with pytest.raises(InvalidTickerSymbol) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=InvalidTickerSymbol,
            context={"ticker": "AAPL", "side": "buy", "quantity": 10},
        )
    msg = str(exc_info.value)
    assert "(ticker=AAPL, side=buy, quantity=10)" in msg, (
        f"Expected exact insertion-ordered fragment "
        f"'(ticker=AAPL, side=buy, quantity=10)' in message, got: {msg!r}"
    )


def test_dispatcher_empty_context_dict_treated_as_no_context():
    """An empty context dict must not leak ``()`` into the message."""
    err = _http_error(404)
    with pytest.raises(RobinhoodResourceError) as exc_info:
        _raise_for_http_error(
            err, fallback_exc=RobinhoodResourceError, context={}
        )
    assert "()" not in str(exc_info.value)


def test_format_context_none_and_empty_dict_equivalent():
    """``_format_context(None)`` and ``_format_context({})`` must both
    return ``""`` (byte-identical).

    Issue #161: the dispatcher BC branch hinges on ``_format_context``
    returning a falsy value for both "no context" cases — callers that
    explicitly pass ``context={}`` (e.g. when building a context
    programmatically and no fields applied) must get the same legacy
    message as callers that omit the kwarg entirely. Pinning the
    contract directly on the helper is more precise than relying on
    downstream ``"()" not in msg`` checks, which only catches one
    failure mode (stray parentheses).
    """
    from pyrh.robinhood import _format_context

    assert _format_context(None) == ""
    assert _format_context({}) == ""
    assert _format_context(None) == _format_context({})


# ---------------------------------------------------------------------------
# 5xx / 429 branches also carry context
# ---------------------------------------------------------------------------


def test_dispatcher_context_kwarg_with_5xx():
    """5xx branch must include context in the RobinhoodServerError message."""
    err = _http_error(500)
    with pytest.raises(RobinhoodServerError) as exc_info:
        _raise_for_http_error(err, context={"order_id": "abc-500"})
    msg = str(exc_info.value)
    assert "500" in msg
    assert "order_id=abc-500" in msg


def test_dispatcher_context_kwarg_with_429():
    """429 branch must include context in the RobinhoodRateLimitError message."""
    err = _http_error(429, headers={"Retry-After": "7"})
    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        _raise_for_http_error(err, context={"ticker": "GME"})
    msg = str(exc_info.value)
    assert "ticker=GME" in msg
    # retry_after int attribute preserved
    assert exc_info.value.retry_after == 7


# ---------------------------------------------------------------------------
# Non-string context values render via str()
# ---------------------------------------------------------------------------


def test_dispatcher_context_non_string_values_stringified():
    """Non-string context values (ints, floats) must stringify cleanly."""
    err = _http_error(404)
    with pytest.raises(RobinhoodResourceError) as exc_info:
        _raise_for_http_error(
            err,
            fallback_exc=RobinhoodResourceError,
            context={"quantity": 42, "price": 1.5},
        )
    msg = str(exc_info.value)
    assert "quantity=42" in msg
    assert "price=1.5" in msg


# ---------------------------------------------------------------------------
# BC invariant: empty context preserves legacy ``exc.args == ()`` tuple
# ---------------------------------------------------------------------------
#
# Round-2 guard (PR #16 review, Guard 1): the PR's BC invariant claims
# "empty context → byte-identical legacy message." That holds for ``str(exc)``
# but BREAKS on ``exc.args``:
#
#   Legacy pre-#150: ``InvalidTickerSymbol()`` → ``.args == ()``
#   PR #150 v1:      ``InvalidTickerSymbol()`` → ``.args == ('',)``
#                    (because ``__init__`` does ``super().__init__("")``)
#
# A defensive caller doing ``if not exc.args:`` would silently change behaviour.
# We pin the tuple to ``()`` so the full BC invariant is honoured — the
# exception is indistinguishable from a legacy construction, not just in
# ``str()`` but in the full ``.args`` shape.


@pytest.mark.parametrize(
    "exc_cls",
    [
        InvalidTickerSymbol,
        InvalidOptionId,
        RobinhoodResourceError,
        RobinhoodOrderSubmissionError,
    ],
)
def test_empty_context_preserves_legacy_empty_args_tuple(exc_cls):
    """BC invariant: ``exc_cls()`` with no context has ``.args == ()`` (legacy)."""
    exc = exc_cls()
    assert exc.args == (), (
        f"BC break on .args: {exc_cls.__name__}() has {exc.args!r}, expected ()"
    )


@pytest.mark.parametrize(
    "exc_cls,expected_prefix",
    [
        (InvalidTickerSymbol, "Invalid or unknown ticker symbol"),
        (InvalidOptionId, "Invalid or unknown option id"),
        (RobinhoodResourceError, "Robinhood resource error"),
        (RobinhoodOrderSubmissionError, "Order submission or cancellation failed"),
    ],
)
def test_non_empty_context_populates_args_tuple(exc_cls, expected_prefix):
    """Regression guard: non-empty context populates ``.args`` with the full message."""
    exc = exc_cls("ticker=AAPL")
    assert len(exc.args) == 1, f"{exc_cls.__name__}: expected 1-tuple, got {exc.args!r}"
    assert expected_prefix in exc.args[0]
    assert "ticker=AAPL" in exc.args[0]


def test_empty_context_preserves_legacy_empty_str():
    """Sanity check: ``str(exc_cls())`` remains empty (legacy pre-#150 behaviour)."""
    # Pre-#150: ``str(InvalidTickerSymbol())`` returns '' because
    # ``str(Exception())`` is '' (Python default). The round-2 fix keeps this
    # while also fixing ``.args``.
    for cls in (
        InvalidTickerSymbol,
        InvalidOptionId,
        RobinhoodResourceError,
        RobinhoodOrderSubmissionError,
    ):
        assert str(cls()) == "", f"{cls.__name__}() str changed: {str(cls())!r}"
