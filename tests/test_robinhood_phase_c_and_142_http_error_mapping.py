# coding=utf-8
"""HTTP status-code -> exception mapping for the profile + quote/historical
methods on ``pyrh.robinhood.Robinhood``.

This module closes out issue #137's umbrella scope (Phase C — profile
endpoints) and addresses issue #142 (quote/historical data scope gap
discovered during PR #11 review).

History:

    * Issue #79 / PR #5 wired ``_raise_for_http_error`` at the quote /
      fundamentals sites.
    * Issue #125 / PR #8 generalised the dispatcher to options.
    * Issue #135 / PR #9 wired it on the 5 remaining options methods.
    * Issue #137 Phase A / PR #10 wired the 6 trading + portfolio methods
      (``portfolio``, ``order_history``, ``dividends``, ``positions``,
      ``securities_owned``, ``get_watchlists``).
    * Issue #137 Phase B / PR #11 wired the 4 discovery / ancillary methods
      (``get_tickers_by_tag``, ``all_instruments``, ``get_popularity``,
      ``get_news``).
    * This module (Phase C + #142) wires the last remaining ``get_url``
      call sites discovered during PR #11 review:

        * ``user`` — profile endpoint, no ticker input.
          (The umbrella issue lists this as ``get_user``; actual method
          name on the class is ``user``.)
        * ``get_account`` — profile endpoint, no ticker input.
        * ``get_stock_marketdata`` — takes a list of instruments; ticker
          semantics fit.
        * ``get_historical_quotes`` — takes a ticker; ticker semantics fit.
        * Also wrapped opportunistically: ``investment_profile`` and
          ``get_symbol_from_instrument_url`` — surfaced by the surface-scan
          AST guard added at the bottom of this module. Both are profile /
          resource-lookup endpoints, so ``RobinhoodResourceError`` fits.

Contract (same dispatch, fallback varies by semantic):

    * 5xx             -> ``RobinhoodServerError``   (message contains status)
    * 429             -> ``RobinhoodRateLimitError`` (with ``Retry-After``)
    * 4xx (404, etc.) -> fallback per method (see ``_fallback_for`` below)
    * HTTPError w/ no ``.response`` -> fallback per method (defensive)

Fallback rationale (per-method):

    * ``user``, ``get_account``, ``investment_profile`` — profile
      endpoints, no ticker input. 4xx means the authenticated user's
      profile resource is unavailable -> ``RobinhoodResourceError``.
    * ``get_symbol_from_instrument_url`` — takes an instrument URL
      (resource identifier, not a ticker). 4xx means the instrument
      resource is unavailable -> ``RobinhoodResourceError``.
    * ``get_stock_marketdata`` — takes instruments list and delegates to
      ``urls.market_data_quotes``. Callers tend to pass ticker-derived
      instruments, and the legacy "bad ticker" signal fits best for
      user-facing errors. Fallback: ``InvalidTickerSymbol``.
    * ``get_historical_quotes`` — takes a ticker. Legacy "bad ticker"
      signal fits. Fallback: ``InvalidTickerSymbol``.
"""
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the Phase A / B / options-methods test modules)
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
# dummy args.
METHOD_INVOKERS = {
    "user": lambda rh: rh.user(),
    "get_account": lambda rh: rh.get_account(),
    "get_stock_marketdata": lambda rh: rh.get_stock_marketdata(
        ["https://example/inst/xyz/"]
    ),
    "get_historical_quotes": lambda rh: rh.get_historical_quotes(
        "AAPL", "day", "year"
    ),
    "investment_profile": lambda rh: rh.investment_profile(),
    "get_symbol_from_instrument_url": lambda rh: rh.get_symbol_from_instrument_url(
        "https://example/inst/xyz/"
    ),
}

# The 4 methods explicitly called out in the task spec — these are the
# umbrella-closing scope. Other methods covered opportunistically.
SPEC_METHOD_NAMES = [
    "user",
    "get_account",
    "get_stock_marketdata",
    "get_historical_quotes",
]

# All methods wrapped in this PR, including opportunistically-discovered
# profile / resource-lookup methods.
ALL_METHOD_NAMES = list(METHOD_INVOKERS.keys())


def _fallback_for(method_name):
    """Expected fallback class for 4xx-not-429 + no-response paths."""
    from pyrh.exceptions import InvalidTickerSymbol, RobinhoodResourceError

    return {
        "user": RobinhoodResourceError,
        "get_account": RobinhoodResourceError,
        "investment_profile": RobinhoodResourceError,
        "get_symbol_from_instrument_url": RobinhoodResourceError,
        "get_stock_marketdata": InvalidTickerSymbol,
        "get_historical_quotes": InvalidTickerSymbol,
    }[method_name]


def _make_fake_get_url(error_factory):
    """Return a simple ``get_url`` mock that raises on every call.

    None of the Phase C / #142 methods chain through already-wrapped
    upstream calls, so the target call is always at index 0.
    """

    def fake_get_url(self, *args, **kwargs):
        raise error_factory()

    return fake_get_url


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError  (the primary bug being fixed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", ALL_METHOD_NAMES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_phase_c_and_142_methods_5xx_raises_RobinhoodServerError(method_name, status):
    from pyrh.exceptions import (
        InvalidTickerSymbol,
        RobinhoodResourceError,
        RobinhoodServerError,
    )

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(lambda: _http_error(status))

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


@pytest.mark.parametrize("method_name", ALL_METHOD_NAMES)
def test_phase_c_and_142_methods_429_raises_RobinhoodRateLimitError(method_name):
    from pyrh.exceptions import (
        InvalidTickerSymbol,
        RobinhoodRateLimitError,
        RobinhoodResourceError,
    )

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        lambda: _http_error(429, headers={"Retry-After": "13"})
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert not isinstance(exc_info.value, RobinhoodResourceError)
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    assert getattr(exc_info.value, "retry_after", None) == 13


@pytest.mark.parametrize("method_name", ALL_METHOD_NAMES)
def test_phase_c_and_142_methods_429_without_retry_after_header(method_name):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(lambda: _http_error(429))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# 4xx (404)  ->  per-method fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", ALL_METHOD_NAMES)
def test_phase_c_and_142_methods_4xx_raises_correct_fallback(method_name):
    expected = _fallback_for(method_name)
    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(lambda: _http_error(404))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(expected):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  per-method fallback (defensive)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", ALL_METHOD_NAMES)
def test_phase_c_and_142_methods_no_response_raises_fallback(method_name):
    expected = _fallback_for(method_name)
    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        lambda: requests.exceptions.HTTPError("boom -- no response attached"),
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(expected):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# Surface-scan AST guard (addresses issue #144).
#
# Previous Phase-A / Phase-B guards used a fixed allowlist of method names.
# That design missed ``get_stock_marketdata`` and ``get_historical_quotes``
# (issue #142) because those names weren't in the allowlist when the guard
# was written. Fixed allowlists don't catch NEW unwrapped methods.
#
# This surface-scan walks ALL ``Robinhood`` methods, finds any that call
# ``self.get_url(...)`` outside a ``try`` block (or without a direct
# ``_raise_for_http_error`` call), and asserts the method name is in the
# known-exempt allowlist. Any future unwrapped ``get_url`` caller will fail
# this test, forcing the author to either wrap the call or add an explicit
# allowlist entry with a reviewer-visible justification.
#
# Scope: ``get_url`` only. Post / put / delete paths on
# ``submit_buy_order`` / ``submit_sell_order`` / ``place_order`` are
# known unwrapped (pre-existing scope, not #137 / #142); a follow-up issue
# tracks them separately rather than silently widening this PR.
# ---------------------------------------------------------------------------


# Methods on ``Robinhood`` that are intentionally NOT wrapped in a
# ``try/except requests.HTTPError`` dispatcher. Each entry requires a
# justification comment — adding a name to this list should be a deliberate
# reviewer-visible decision.
EXEMPT_UNWRAPPED_GET_URL_METHODS = frozenset(
    {
        # ``get_url`` is the dispatcher seam itself — it delegates to
        # ``SessionManager.get``, which handles the request. Wrapping it
        # would wrap everything twice.
        "get_url",
    }
)


def test_no_unwrapped_get_url_call_sites_on_robinhood_class():
    """Surface scan: no ``Robinhood`` method may call ``self.get_url(...)``
    outside a ``try`` block unless explicitly allowlisted.

    Rationale: issue #142 surfaced when PR #11 review asked "did we miss
    any methods?" and found ``get_stock_marketdata`` and
    ``get_historical_quotes`` had been missed by the fixed-name Phase-B
    guard. A fixed allowlist can't catch a method that didn't exist when
    the allowlist was written. This test inverts the check: scan the code,
    find unwrapped call sites, require each to justify its exemption.
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

    robinhood_class = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
        ),
        None,
    )
    assert robinhood_class is not None, "Robinhood class not found in robinhood.py"

    def _is_self_get_url_call(node: ast.AST) -> bool:
        """True iff ``node`` is ``self.get_url(...)``."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr != "get_url":
            return False
        value = func.value
        if not isinstance(value, ast.Name):
            return False
        return value.id == "self"

    def _inside_try(method: ast.FunctionDef, target: ast.Call) -> bool:
        """True iff ``target`` is a descendant of some ``ast.Try`` node
        whose ``try`` body lives inside ``method``."""
        for node in ast.walk(method):
            if isinstance(node, ast.Try):
                # Walk each Try's body + handlers + else + finalbody; if
                # target is among those descendants, it's inside a try.
                for child in ast.walk(node):
                    if child is target:
                        return True
        return False

    def _has_direct_dispatcher_call(method: ast.FunctionDef) -> bool:
        """True iff method body directly invokes ``_raise_for_http_error``.

        Defensive: a method could conceivably dispatch manually (no try
        block, but explicit call to the helper). None of the current
        methods do this, but the Phase-A guard allows it, so mirror that.
        """
        for node in ast.walk(method):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "_raise_for_http_error":
                    return True
        return False

    offenders = []  # list of (method_name, line_no)
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in EXEMPT_UNWRAPPED_GET_URL_METHODS:
            continue
        has_dispatcher = _has_direct_dispatcher_call(method)
        for node in ast.walk(method):
            if not _is_self_get_url_call(node):
                continue
            if _inside_try(method, node):
                continue
            if has_dispatcher:
                # Method dispatches manually somewhere — trust it.
                continue
            offenders.append((method.name, node.lineno))

    if offenders:
        formatted = "\n".join(f"  - {name} at line {lineno}" for name, lineno in offenders)
        pytest.fail(
            "Unwrapped self.get_url(...) call sites found on Robinhood class "
            "(issue #137 umbrella + #142 scope gap):\n"
            f"{formatted}\n\n"
            "Each call site must either be inside a ``try/except "
            "requests.HTTPError`` block that invokes "
            "``_raise_for_http_error(e, fallback_exc=<per-method>)``, "
            "or the method name must be added to "
            "``EXEMPT_UNWRAPPED_GET_URL_METHODS`` above with a "
            "justification comment explaining why it is intentionally "
            "unwrapped."
        )
