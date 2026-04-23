# coding=utf-8
"""HTTP status-code -> exception mapping for the discovery / ancillary
methods on ``pyrh.robinhood.Robinhood`` (issue #137, Phase B).

Issue #79 / PR #5 wired ``_raise_for_http_error`` at the quote / fundamentals
sites. Issue #125 / PR #8 generalised the dispatcher. Issue #135 / PR #9
wired it on the 5 remaining options-endpoint methods. Issue #137 Phase A /
PR #10 wired it on the 6 trading-path + portfolio methods. Phase B (this
module) covers the 4 discovery / ancillary methods that still leak raw
``requests.HTTPError`` on 5xx / 429:

    * ``get_tickers_by_tag`` — discovery by tag
    * ``all_instruments``   — discovery paginator from positions
    * ``get_popularity``    — popularity count for a single ticker
    * ``get_news``          — news feed for a single ticker

Contract (same dispatch, fallback varies by semantic):

    * 5xx             -> ``RobinhoodServerError``   (message contains status)
    * 429             -> ``RobinhoodRateLimitError`` (with ``Retry-After``)
    * 4xx (404, etc.) -> fallback per method (see ``METHOD_FALLBACKS`` below)
    * HTTPError w/ no ``.response`` -> fallback per method (defensive)

Fallback rationale (per-method):

    * ``get_tickers_by_tag`` — takes a tag name, not a ticker. A 4xx is
      "the tag does not exist" — a resource lookup failure.
      Fallback: ``RobinhoodResourceError``.
    * ``all_instruments``   — no user input; paginates over positions. A
      4xx here means an instrument URL served by Robinhood's own positions
      response failed. Resource lookup failure.
      Fallback: ``RobinhoodResourceError``.
    * ``get_popularity``    — takes a ticker. The legacy "bad ticker"
      signal fits. Fallback: ``InvalidTickerSymbol``.
    * ``get_news``          — takes a ticker. Same as above.
      Fallback: ``InvalidTickerSymbol``.
"""
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the Phase A / options-methods test modules)
# ---------------------------------------------------------------------------


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


# Per-method callable adapter. Each entry returns a zero-arg callable that
# invokes the target method on the supplied Robinhood instance with minimal
# dummy args (a ticker where needed).
METHOD_INVOKERS = {
    "get_tickers_by_tag": lambda rh: rh.get_tickers_by_tag("top-movers"),
    "all_instruments": lambda rh: rh.all_instruments(),
    "get_popularity": lambda rh: rh.get_popularity("AAPL"),
    "get_news": lambda rh: rh.get_news("AAPL"),
}

METHOD_NAMES = list(METHOD_INVOKERS.keys())


def _fallback_for(method_name):
    """Expected fallback class for 4xx-not-429 + no-response paths."""
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodResourceError

    return {
        "get_tickers_by_tag": RobinhoodResourceError,
        "all_instruments": RobinhoodResourceError,
        "get_popularity": InvalidTickerSymbol,
        "get_news": InvalidTickerSymbol,
    }[method_name]


# Some of these methods chain through already-wrapped upstream calls:
#   * ``get_popularity`` -> ``quote_data`` (already wrapped) then
#     ``get_url(urls.instruments(..., "popularity"))`` (target).
#   * ``all_instruments`` -> ``positions`` (already wrapped) then
#     iterates ``get_url(position["instrument"])`` (target).
#   * ``get_tickers_by_tag`` -> ``get_url(urls.tags(tag))`` (target #1)
#     then iterates ``get_url(instrument)`` (target #2).
#   * ``get_news`` -> single ``get_url(urls.news(...))`` (target).
#
# To force the error onto the *Phase-B* call site, we patch at the right
# seam. For methods that chain through ``quote_data`` / ``positions``, we
# need the upstream to succeed first. We patch ``get_url`` on Robinhood and
# schedule success for pre-target calls, then raise.
METHOD_FIRST_UNWRAPPED_CALL_INDEX = {
    "get_tickers_by_tag": 0,   # first get_url is the target (urls.tags(tag))
    "all_instruments": 1,      # positions() first (calls get_url once), then loop
    "get_popularity": 1,       # quote_data's get_url first, then popularity
    "get_news": 0,             # single get_url
}


def _make_fake_get_url(target_method_name, error_factory):
    """Build a ``get_url`` mock that succeeds for pre-target calls, then raises.

    Success stubs are shaped to satisfy the upstream wrapped call so control
    reaches the Phase-B target site before the error is injected.
    """
    skip = METHOD_FIRST_UNWRAPPED_CALL_INDEX[target_method_name]
    counter = {"n": 0}

    # Per-method success stubs for upstream (already-wrapped) calls.
    def _success_stub_for(method_name, call_i):
        if method_name == "get_popularity":
            # First call: quote_data's get_url -> needs {"instrument": "<url>"}
            return {"instrument": "https://example/instruments/xyz/"}
        if method_name == "all_instruments":
            # First call: positions() -> needs {"results": [{"instrument": "<url>"}]}
            return {"results": [{"instrument": "https://example/instruments/xyz/"}]}
        # Unused for methods where skip == 0, but defined defensively.
        return {}

    def fake_get_url(self, *args, **kwargs):
        i = counter["n"]
        counter["n"] += 1
        if i < skip:
            return _success_stub_for(target_method_name, i)
        raise error_factory()

    return fake_get_url


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError  (the primary bug being fixed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_phase_b_methods_5xx_raises_server_error(method_name, status):
    from pyrh.exceptions import (
        InvalidTickerSymbol,
        RobinhoodResourceError,
        RobinhoodServerError,
    )

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(status))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    # Must NOT be any fallback exception (the bug being fixed).
    assert not isinstance(exc_info.value, RobinhoodResourceError)
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    # Message should mention the status for diagnostics / logs.
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with + without Retry-After)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_phase_b_methods_429_raises_rate_limit_error_with_retry_after(method_name):
    from pyrh.exceptions import (
        InvalidTickerSymbol,
        RobinhoodRateLimitError,
        RobinhoodResourceError,
    )

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name, lambda: _http_error(429, headers={"Retry-After": "11"})
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert not isinstance(exc_info.value, RobinhoodResourceError)
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    assert getattr(exc_info.value, "retry_after", None) == 11


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_phase_b_methods_429_without_retry_after_header(method_name):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(429))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# 4xx (404)  ->  per-method fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_phase_b_methods_404_raises_correct_fallback(method_name):
    expected = _fallback_for(method_name)
    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(404))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(expected):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  per-method fallback (defensive)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_phase_b_methods_http_error_without_response_raises_fallback(method_name):
    expected = _fallback_for(method_name)
    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name,
        lambda: requests.exceptions.HTTPError("boom -- no response attached"),
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(expected):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# Symmetry guard: every Phase-B method must wrap its ``get_url`` call(s) in
# a try/except or invoke ``_raise_for_http_error``. Mirrors the Phase-A
# symmetry guard in test_robinhood_trading_portfolio_http_error_mapping.py.
# ---------------------------------------------------------------------------


PHASE_B_METHOD_NAMES = frozenset(
    {
        "get_tickers_by_tag",
        "all_instruments",
        "get_popularity",
        "get_news",
    }
)


def test_all_phase_b_methods_have_http_error_handling():
    """AST-level guard: every Phase-B method must have dispatcher wiring.

    Scope: the 4 discovery / ancillary methods tracked by issue #137 Phase B.
    A method is considered "wired" if its body contains either a ``try``
    block OR a call to ``_raise_for_http_error``.
    """
    import ast
    from pathlib import Path

    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )
    tree = ast.parse(source)

    def _method_calls_http(node: ast.FunctionDef) -> bool:
        http_call_names = {"get_url", "get", "post", "put", "delete", "patch"}
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr in http_call_names:
                    return True
        return False

    def _has_dispatcher(node: ast.FunctionDef) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id == "_raise_for_http_error":
                    return True
            if isinstance(n, ast.Try):
                return True
        return False

    robinhood_class = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
        ),
        None,
    )
    assert robinhood_class is not None, "Robinhood class not found in robinhood.py"

    missing = []
    seen = set()
    for node in ast.walk(robinhood_class):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in PHASE_B_METHOD_NAMES:
            continue
        seen.add(node.name)
        if not _method_calls_http(node):
            missing.append(f"{node.name} (no http call found — did the method change?)")
            continue
        if not _has_dispatcher(node):
            missing.append(node.name)

    not_found = PHASE_B_METHOD_NAMES - seen
    assert not not_found, (
        f"Phase B methods not found on Robinhood class: {sorted(not_found)}. "
        "Has a method been renamed or removed? Update PHASE_B_METHOD_NAMES."
    )
    assert not missing, (
        "Phase B methods missing HTTPError dispatcher "
        f"(see issue #137 Phase B): {missing}. "
        "Wrap the HTTP call in try/except requests.HTTPError and call "
        "_raise_for_http_error(e, fallback_exc=<per-method>)."
    )
