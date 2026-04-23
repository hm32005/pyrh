# coding=utf-8
"""HTTP status-code -> exception mapping for the remaining 5 options-endpoint
methods on ``pyrh.robinhood.Robinhood`` (issue #135).

Issue #125 (and PR #8) generalised ``_raise_for_http_error`` and wired it at
the options-quote site (``get_option_market_data``). Issue #135 tracks the
5 sibling options-endpoint methods that still call ``self.get_url(...)`` with
NO translation, so a 5xx outage or 429 rate-limit at the Robinhood options
backend raises raw ``requests.HTTPError`` to the caller:

    * ``get_options``
    * ``options_owned``
    * ``get_option_marketdata``
    * ``get_option_chain_id``
    * ``get_option_quote``

Contract (identical to ``get_option_market_data``):

    * 5xx             -> ``RobinhoodServerError``   (message contains status)
    * 429             -> ``RobinhoodRateLimitError`` (with ``Retry-After``)
    * 4xx (404, etc.) -> ``InvalidOptionId``        (legacy "bad input" signal)
    * HTTPError w/ no ``.response`` -> ``InvalidOptionId`` (defensive)
"""
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors test_robinhood_options_http_error_mapping.py)
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
    "get_options": lambda rh: rh.get_options("AAPL", ["2026-05-15"], "call"),
    "options_owned": lambda rh: rh.options_owned(),
    "get_option_marketdata": lambda rh: rh.get_option_marketdata("0000-option-id"),
    "get_option_chain_id": lambda rh: rh.get_option_chain_id("AAPL"),
    "get_option_quote": lambda rh: rh.get_option_quote(
        "AAPL", 180, "2026-05-15", "call"
    ),
}

METHOD_NAMES = list(METHOD_INVOKERS.keys())


# Some options methods chain through earlier ``get_url`` calls that are
# *already* wrapped (e.g. ``get_options`` calls ``quote_data`` which has its
# own HTTPError dispatcher). We need the UNWRAPPED call to be the one that
# raises, otherwise the test exercises the already-correct upstream path and
# not the bug we're fixing. This map says "how many ``get_url`` calls to let
# succeed before raising".
#
# Per-method call chain (see pyrh/robinhood.py):
#
#   get_options:
#     1. self.quote_data(stock)          -> get_url(#1, quotes)      [WRAPPED]
#     2. self.get_url(<instrument url>)  -> get_url(#2, instrument)  [UNWRAPPED — target]
#     3. self.get_url(urls.chain(...))   -> get_url(#3, chains)      [UNWRAPPED]
#     4. self.get_url(urls.options(...)) -> get_url(#4, options)     [UNWRAPPED]
#
#   options_owned:         single get_url (index 0, UNWRAPPED — target)
#   get_option_marketdata: single get_url (index 0, UNWRAPPED — target)
#   get_option_chain_id:
#     1. self.get_url(instruments?symbol=...)  [UNWRAPPED — target]
#     2. self.get_url(options/chains/?...)     [UNWRAPPED]
#
#   get_option_quote:
#     1. self.get_url(options/instruments/?...)  [UNWRAPPED — target]
#     2. (only if results) self.get_option_marketdata(option_id)  [already-fixed via #125]
#
# We raise on the FIRST unwrapped call so the test is deterministic and
# exercises exactly the new dispatcher wiring.
METHOD_FIRST_UNWRAPPED_CALL_INDEX = {
    "get_options": 1,          # skip call #0 (quote_data-wrapped)
    "options_owned": 0,
    "get_option_marketdata": 0,
    "get_option_chain_id": 0,
    "get_option_quote": 0,
}


def _make_fake_get_url(target_method_name, error_factory, success_stub=None):
    """Build a ``get_url`` mock that succeeds for pre-target calls, then raises.

    Why: see ``METHOD_FIRST_UNWRAPPED_CALL_INDEX``. We want the error to hit
    the specific call site that issue #135 is about, not an already-wrapped
    upstream call.

    Args:
        target_method_name: which entry in ``METHOD_FIRST_UNWRAPPED_CALL_INDEX``
            to look up.
        error_factory: zero-arg callable returning the exception to raise.
        success_stub: optional zero-arg callable returning the fake JSON shape
            the pre-target calls need. Defaults to a shape that keeps
            ``quote_data`` / ``get_options`` / ``get_option_chain_id`` happy
            (those are the only methods with pre-target successes).
    """
    skip = METHOD_FIRST_UNWRAPPED_CALL_INDEX[target_method_name]

    def _default_success():
        # Enough shape to satisfy the pre-target consumers:
        #   * quote_data:   result["instrument"] must be indexable
        #   * get_options call #1: result["id"] must exist (instrument payload)
        #   * get_option_chain_id call #0: result["results"][0]["id"]
        return {
            "instrument": "https://example/instruments/xxx/",
            "id": "dummy-instrument-id",
            "results": [{"id": "dummy-chain-id", "can_open_position": True}],
        }

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
def test_options_methods_5xx_raises_server_error(method_name, status):
    from pyrh.exceptions import InvalidOptionId, RobinhoodServerError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(status))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    # Must NOT be InvalidOptionId (the bug being fixed).
    assert not isinstance(exc_info.value, InvalidOptionId)
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with Retry-After surfaced)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_options_methods_429_raises_rate_limit_error_with_retry_after(method_name):
    from pyrh.exceptions import InvalidOptionId, RobinhoodRateLimitError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name, lambda: _http_error(429, headers={"Retry-After": "7"})
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert not isinstance(exc_info.value, InvalidOptionId)
    assert getattr(exc_info.value, "retry_after", None) == 7


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_options_methods_429_without_retry_after_header(method_name):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(429))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            METHOD_INVOKERS[method_name](rh)

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# 4xx (404)  ->  InvalidOptionId  (legacy behaviour preserved)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_options_methods_404_raises_invalid_option_id(method_name):
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(method_name, lambda: _http_error(404))

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  InvalidOptionId (defensive fallback)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method_name", METHOD_NAMES)
def test_options_methods_http_error_without_response_raises_invalid_option_id(
    method_name,
):
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()
    fake_get_url = _make_fake_get_url(
        method_name,
        lambda: requests.exceptions.HTTPError("boom -- no response attached"),
    )

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId):
            METHOD_INVOKERS[method_name](rh)


# ---------------------------------------------------------------------------
# Symmetry guard: every ``option``-named method that hits an HTTP call must
# either wrap a try/except HTTPError or invoke ``_raise_for_http_error``.
#
# This prevents a future options-endpoint method being added without
# dispatcher wiring, which is how issue #135 existed in the first place.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tight AST guard implementation (#141 / #158).
#
# See the Phase-A guard module for the full rationale. Summary: the previous
# ``_has_dispatcher`` returned True on any ``ast.Try`` in the method body,
# even when the try did not wrap the HTTP call. Consolidated here via the
# shared helpers in ``tests/_ast_guard_helpers.py``.
#
# Options scope: methods on ``Robinhood`` whose name contains ``option``
# (case-insensitive). Discovered dynamically because issue #135 is about
# "any method in the options surface" — we do not maintain a fixed list.
# ---------------------------------------------------------------------------


from tests._ast_guard_helpers import (  # noqa: E402
    _inside_try_with_dispatcher,
    _is_self_get_url_call,
)


def _collect_options_offenders(source):
    """Return a list of ``(method_name, lineno)`` for every ``self.get_url(...)``
    call site on a ``Robinhood`` method whose name contains ``option``
    (case-insensitive) that is NOT inside a dispatching try/except.
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
        return []

    offenders = []
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if "option" not in method.name.lower():
            continue
        for call in ast.walk(method):
            if not _is_self_get_url_call(call):
                continue
            if _inside_try_with_dispatcher(method, call):
                continue
            offenders.append((method.name, call.lineno))
    return offenders


def test_all_options_methods_have_http_error_handling():
    """AST-level guard: every ``option``-named method's ``self.get_url(...)``
    call sites must live inside a ``try/except`` whose handler invokes
    ``_raise_for_http_error`` (tightened per #141 / #158).
    """
    from pathlib import Path

    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )

    offenders = _collect_options_offenders(source)

    if offenders:
        formatted = "\n".join(
            f"  - {name} at line {lineno}" for name, lineno in offenders
        )
        pytest.fail(
            "Options-endpoint methods with unwrapped self.get_url(...) "
            f"call sites (see issue #135): \n{formatted}\n\n"
            "Wrap the HTTP call in try/except requests.HTTPError and call "
            "_raise_for_http_error(e, fallback_exc=InvalidOptionId)."
        )


# ---------------------------------------------------------------------------
# #141 / #158 — tight-guard boundary tests for options.
# ---------------------------------------------------------------------------


def _fabricate_options_source_with(method_body):
    """Build a minimal ``Robinhood`` source containing a single
    option-named method whose body is injected verbatim.
    """
    import textwrap

    injected = textwrap.indent(textwrap.dedent(method_body).strip("\n") + "\n", "    ")
    return "class Robinhood:\n" + injected


def test_options_guard_rejects_method_with_unrelated_try_and_unwrapped_get_url():
    """RED for #158 on options: option-named method with an unrelated try
    and an unwrapped ``self.get_url(...)`` must be flagged. Loose guard
    would accept due to ANY ast.Try.
    """
    trap = """
def get_option_market_data(self, option_id):
    try:
        option_id = str(option_id)
    except TypeError:
        pass
    return self.get_url("/marketdata/options/" + option_id)
"""
    source = _fabricate_options_source_with(trap)

    offenders = _collect_options_offenders(source)
    offender_names = [name for name, _ in offenders]
    assert "get_option_market_data" in offender_names, (
        f"tight guard must flag get_option_market_data; got {offenders}"
    )


def test_options_guard_accepts_properly_wrapped_method():
    """GREEN: properly wrapped option-named method must pass."""
    good = """
def get_option_market_data(self, option_id):
    try:
        return self.get_url("/marketdata/options/" + option_id)
    except requests.exceptions.HTTPError as e:
        _raise_for_http_error(e, fallback_exc=InvalidOptionId)
"""
    source = _fabricate_options_source_with(good)

    offenders = _collect_options_offenders(source)
    assert offenders == [], f"expected no offenders; got {offenders}"


def test_options_guard_rejects_try_except_that_does_not_dispatch():
    """Same-shape as #144: try wraps the HTTP call, but the except handler
    raises an unrelated exception instead of dispatching.
    """
    trap = """
def get_option_quote(self, option_id):
    try:
        return self.get_url("/quotes/options/" + option_id)
    except requests.exceptions.HTTPError:
        raise ValueError("bad option")
"""
    source = _fabricate_options_source_with(trap)

    offenders = _collect_options_offenders(source)
    offender_names = [name for name, _ in offenders]
    assert "get_option_quote" in offender_names
