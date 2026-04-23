# coding=utf-8
"""HTTP status-code -> exception mapping for the trading-path + portfolio
methods on ``pyrh.robinhood.Robinhood`` (issue #137, Phase A).

Issue #79 / PR #5 wired ``_raise_for_http_error`` at the quote / fundamentals
sites. Issue #125 / PR #8 generalised the dispatcher. Issue #135 / PR #9
wired it on the 5 remaining options-endpoint methods. Issue #137 is the
umbrella tracking the ~10 non-options ``get_url`` callers that STILL leak
raw ``requests.HTTPError`` on 5xx / 429. Phase A (this test module) covers
the 6 trading-path + portfolio methods:

    * ``portfolio``
    * ``order_history``
    * ``dividends``
    * ``positions``
    * ``securities_owned``
    * ``get_watchlists`` (and its ``watchlists`` alias)

Contract (same dispatch, different fallback class):

    * 5xx             -> ``RobinhoodServerError``   (message contains status)
    * 429             -> ``RobinhoodRateLimitError`` (with ``Retry-After``)
    * 4xx (404, etc.) -> ``RobinhoodResourceError`` (new — Phase A fallback)
    * HTTPError w/ no ``.response`` -> ``RobinhoodResourceError`` (defensive)

Why a new ``RobinhoodResourceError`` instead of reusing ``InvalidTickerSymbol``?
These endpoints don't take a ticker argument — a "bad ticker" signal would
be semantically wrong. The portfolio/orders/watchlists endpoints operate on
the authenticated user's own resources; a 4xx here is "resource not found
or not accessible for this user", not "bad ticker input". See issue #137
for the design discussion.
"""
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the other HTTP-error-mapping test modules)
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
    "portfolio": lambda rh: rh.portfolio(),
    "order_history": lambda rh: rh.order_history(),
    "dividends": lambda rh: rh.dividends(),
    "positions": lambda rh: rh.positions(),
    "securities_owned": lambda rh: rh.securities_owned(),
    "get_watchlists": lambda rh: rh.get_watchlists(),
}

METHOD_NAMES = list(METHOD_INVOKERS.keys())


# None of these methods chain through already-wrapped upstream ``get_url``
# calls (unlike options), so index 0 is always the target call for every
# method. ``get_watchlists`` has up to 3 ``get_url`` calls in sequence, but
# the FIRST one (``urls.WATCHLISTS``) is the unwrapped target; raising there
# correctly short-circuits the loop — which is the behaviour we want.
METHOD_FIRST_UNWRAPPED_CALL_INDEX = {name: 0 for name in METHOD_NAMES}


def _make_fake_get_url(target_method_name, error_factory, success_stub=None):
    """Build a ``get_url`` mock that succeeds for pre-target calls, then raises.

    Since all Phase A methods have their target unwrapped call at index 0,
    this essentially just raises on the first call — but the scaffolding
    mirrors the options-methods test so the two can share a helper later.
    """
    skip = METHOD_FIRST_UNWRAPPED_CALL_INDEX[target_method_name]

    def _default_success():
        # Shape that keeps ``get_watchlists`` (the only multi-call method)
        # happy if the error is scheduled after call #0.
        return {"results": [{"url": "https://example/watchlist/x/", "instrument": "https://example/inst/x/"}]}

    stub = success_stub or _default_success
    counter = {"n": 0}

    def fake_get_url(self, *args, **kwargs):
        i = counter["n"]
        counter["n"] += 1
        if i < skip:
            return stub()
        raise error_factory()

    return fake_get_url


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError  (the primary bug being fixed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_trading_portfolio_methods_5xx_raises_server_error(method_name, status):
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

    # Must NOT be the fallback exception (the bug being fixed).
    assert not isinstance(exc_info.value, RobinhoodResourceError)
    assert not isinstance(exc_info.value, InvalidTickerSymbol)
    # Message should mention the status for diagnostics / logs.
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with + without Retry-After)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_trading_portfolio_methods_429_raises_rate_limit_error_with_retry_after(method_name):
    from pyrh.exceptions import RobinhoodRateLimitError, RobinhoodResourceError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name, lambda: _http_error(429, headers={"Retry-After": "11"})
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert not isinstance(exc_info.value, RobinhoodResourceError)
    assert getattr(exc_info.value, "retry_after", None) == 11


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_trading_portfolio_methods_429_without_retry_after_header(method_name):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(429))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# 4xx (404)  ->  RobinhoodResourceError  (new fallback, Phase A)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_trading_portfolio_methods_404_raises_resource_error(method_name):
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(404))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  RobinhoodResourceError (defensive fallback)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_trading_portfolio_methods_http_error_without_response_raises_resource_error(
    method_name,
):
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name,
        lambda: requests.exceptions.HTTPError("boom -- no response attached"),
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# ``watchlists`` is an alias for ``get_watchlists`` — same contract.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [500, 429, 404])
def test_watchlists_alias_dispatches_identically(status):
    """Regression guard: back-compat ``watchlists`` alias must use the same
    dispatcher as ``get_watchlists``.

    (The alias is declared as ``watchlists = get_watchlists`` in robinhood.py;
    this test pins that it continues to route through the wrapper.)
    """
    from pyrh.exceptions import (
        RobinhoodRateLimitError,
        RobinhoodResourceError,
        RobinhoodServerError,
    )

    expected = {
        500: RobinhoodServerError,
        429: RobinhoodRateLimitError,
        404: RobinhoodResourceError,
    }[status]

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(expected):
            rh.watchlists()


# ---------------------------------------------------------------------------
# Symmetry guard: every Phase-A method must wrap its ``get_url`` call(s) in
# a try/except or invoke ``_raise_for_http_error``.
#
# This prevents a regression where someone removes the wrapper and Phase A
# silently leaks raw HTTPError again (exactly the bug issue #137 exists to
# prevent). Mirrors the options symmetry guard in
# ``test_all_options_methods_have_http_error_handling``.
# ---------------------------------------------------------------------------


PHASE_A_METHOD_NAMES = frozenset(
    {
        "portfolio",
        "order_history",
        "dividends",
        "positions",
        "securities_owned",
        "get_watchlists",
    }
)


# ---------------------------------------------------------------------------
# Tight AST guard implementation (#141 / #158).
#
# Previous pattern (RED — kept in git history for reference):
#
#     def _has_dispatcher(node):
#         for n in ast.walk(node):
#             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
#                 if n.func.id == "_raise_for_http_error":
#                     return True
#             if isinstance(n, ast.Try):
#                 return True  # <-- ANY try anywhere passes!
#         return False
#
# Weakness: a method like ``get_popularity`` doing
#
#     def get_popularity(self, stock):
#         try:
#             json.loads(stock)
#         except json.JSONDecodeError:
#             pass
#         return self.get_url(urls.build_popularity(stock))  # UNWRAPPED!
#
# passes silently under the loose guard. #158 flagged this.
#
# Tight pattern (#141 consolidation): reuse the shared helpers from
# ``tests/_ast_guard_helpers.py`` (introduced by #144 / PR #15). For each
# ``self.get_url(...)`` call in the method, verify it is inside a
# ``try`` body whose except handler invokes ``_raise_for_http_error``.
# ---------------------------------------------------------------------------


from tests._ast_guard_helpers import (  # noqa: E402
    _inside_try_with_dispatcher,
    _is_self_get_url_call,
)


def _collect_phase_a_offenders(source, method_names=PHASE_A_METHOD_NAMES):
    """Return a list of ``(method_name, lineno)`` for every call site in
    ``method_names`` whose ``self.get_url(...)`` is not protected by a
    dispatching try/except.

    Also returns a ``not_found`` set of method names that were expected on
    the ``Robinhood`` class but not present — a renamed-method safety net.
    """
    import ast

    tree = ast.parse(source)
    robinhood_class = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
        ),
        None,
    )
    if robinhood_class is None:
        return [], set(method_names)

    offenders = []
    seen = set()
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name not in method_names:
            continue
        seen.add(method.name)
        for call in ast.walk(method):
            if not _is_self_get_url_call(call):
                continue
            if _inside_try_with_dispatcher(method, call):
                continue
            offenders.append((method.name, call.lineno))

    return offenders, method_names - seen


def test_all_phase_a_methods_have_http_error_handling():
    """AST-level guard: every Phase-A method must have its
    ``self.get_url(...)`` call sites inside a ``try/except`` whose except
    handler invokes ``_raise_for_http_error`` (tightened per #141 / #158).

    Scope: the 6 trading-path + portfolio methods tracked by issue #137
    Phase A. Prior implementation used a weaker ``_has_dispatcher`` that
    returned True on any ``ast.Try`` anywhere in the method body — even a
    try unrelated to the HTTP call. See module docstring above.
    """
    from pathlib import Path

    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )

    offenders, not_found = _collect_phase_a_offenders(source)

    assert not not_found, (
        f"Phase A methods not found on Robinhood class: {sorted(not_found)}. "
        "Has a method been renamed or removed? Update PHASE_A_METHOD_NAMES."
    )
    if offenders:
        formatted = "\n".join(
            f"  - {name} at line {lineno}" for name, lineno in offenders
        )
        pytest.fail(
            "Phase A methods with unwrapped self.get_url(...) call sites "
            f"(see issue #137): \n{formatted}\n\n"
            "Wrap the HTTP call in try/except requests.HTTPError and call "
            "_raise_for_http_error(e, fallback_exc=RobinhoodResourceError)."
        )


# ---------------------------------------------------------------------------
# #141 / #158 — tight-guard boundary tests.
#
# These pin the TIGHT semantic by constructing synthetic method bodies
# that the loose ``_has_dispatcher`` pattern would have accepted but
# which the tightened consolidation MUST reject. They are the RED / GREEN
# spec for the consolidation: they would have FAILED against the old
# weaker implementation (any ast.Try passes), and PASS against the
# tightened one routed through ``_inside_try_with_dispatcher``.
# ---------------------------------------------------------------------------


def _fabricate_robinhood_source_with(method_body):
    """Build a minimal ``pyrh/robinhood.py``-shaped source for the guard
    to parse. The ``method_body`` is injected verbatim as a method of the
    fabricated ``Robinhood`` class (caller provides a ``def`` at col 0).

    The remaining Phase-A methods are generated with proper dispatcher
    wiring so the guard only flags issues with the injected method.
    """
    import textwrap

    injected = textwrap.indent(textwrap.dedent(method_body).strip("\n") + "\n", "    ")
    companions = textwrap.indent(
        textwrap.dedent(
            """
            def order_history(self):
                try:
                    return self.get_url("/orders/")
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
            def dividends(self):
                try:
                    return self.get_url("/dividends/")
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
            def positions(self):
                try:
                    return self.get_url("/positions/")
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
            def securities_owned(self):
                try:
                    return self.get_url("/securities/")
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
            def get_watchlists(self):
                try:
                    return self.get_url("/watchlists/")
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
            """
        ).strip("\n")
        + "\n",
        "    ",
    )
    return "class Robinhood:\n" + injected + companions


def test_phase_a_guard_rejects_method_with_unrelated_try_and_unwrapped_get_url():
    """RED for #158: a Phase-A method with an UNRELATED try + an unwrapped
    ``self.get_url(...)`` must be flagged as an offender. The previous loose
    ``_has_dispatcher`` returned True on ANY ast.Try regardless of whether
    the HTTP call sat inside it — this is the blind spot #158 called out.
    """
    trap = """
def portfolio(self):
    try:
        json.loads(something)
    except json.JSONDecodeError:
        pass
    return self.get_url("/portfolio/")
"""
    source = _fabricate_robinhood_source_with(trap)

    offenders, not_found = _collect_phase_a_offenders(source)

    assert not not_found, f"all Phase-A methods must be present: {not_found}"
    offender_names = [name for name, _ in offenders]
    assert "portfolio" in offender_names, (
        "tight guard must flag ``portfolio`` — the try is unrelated to the "
        "unwrapped self.get_url(...) call. Got: "
        f"{offenders}"
    )


def test_phase_a_guard_accepts_method_with_proper_dispatcher_wrap():
    """GREEN: a Phase-A method with correct dispatcher wiring must pass."""
    good = """
def portfolio(self):
    try:
        return self.get_url("/portfolio/")
    except requests.exceptions.HTTPError as e:
        _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)
"""
    source = _fabricate_robinhood_source_with(good)

    offenders, not_found = _collect_phase_a_offenders(source)

    assert not not_found
    assert offenders == [], f"should have no offenders; got {offenders}"


def test_phase_a_guard_rejects_method_with_try_but_non_dispatching_handler():
    """Same-shape as #144 / cancel_order pre-PR #13: try/except exists AND
    wraps the call, but the except handler raises an unrelated exception
    instead of dispatching via ``_raise_for_http_error``.
    """
    trap = """
def portfolio(self):
    try:
        return self.get_url("/portfolio/")
    except requests.exceptions.HTTPError:
        raise ValueError("bad")
"""
    source = _fabricate_robinhood_source_with(trap)

    offenders, _ = _collect_phase_a_offenders(source)
    offender_names = [name for name, _ in offenders]
    assert "portfolio" in offender_names
