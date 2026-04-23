# coding=utf-8
"""HTTP status-code -> exception mapping for POST-path order submission
methods on ``pyrh.robinhood.Robinhood``.

Closes investment-system-docs issue #147.

Background
----------
Issue #148 (PR #13) wired the shared ``_raise_for_http_error`` dispatcher
onto the two ``self.get_url(...)`` call sites in ``cancel_order`` and
introduced :class:`RobinhoodOrderSubmissionError` for 4xx fallbacks. It
was scoped to GET paths only — the POST (write-path) call sites in the
order-submission methods were left unwrapped and still raised
``ValueError`` on HTTPError.

This module wires the same dispatcher onto all 5 POST call sites:

    * ``submit_sell_order`` -- ``self.post(urls.orders(), data=payload)``
    * ``submit_buy_order``  -- ``self.post(urls.orders(), data=payload)``
    * ``place_order``       -- ``self.post(urls.orders(), data=payload)``
    * ``cancel_order`` str-branch  -- ``self.post(order["cancel"])`` retry
    * ``cancel_order`` dict-branch -- ``self.post(order["cancel"])`` retry

Reuses :class:`RobinhoodOrderSubmissionError` introduced by #148; no new
exception class is needed.

Contract (per-site)
-------------------
When the POST call raises ``requests.HTTPError``:

    * 5xx                         -> ``RobinhoodServerError``
    * 429                         -> ``RobinhoodRateLimitError`` (Retry-After)
    * 4xx (other)                 -> ``RobinhoodOrderSubmissionError``
    * HTTPError w/ no ``.response`` -> ``RobinhoodOrderSubmissionError`` (defensive)

MUST NOT raise plain ``ValueError`` on any of these paths (the legacy
contract that #148 already broke on the GET paths).

Idempotency caveat
------------------
When a POST order-submission returns 5xx, the caller MUST verify whether
the order actually went through (idempotency key + order-status query).
The dispatcher converts 5xx to ``RobinhoodServerError`` but DOES NOT
retry automatically — adding retry here would risk duplicate orders.
This is documented in the ``RobinhoodOrderSubmissionError`` docstring.

Exemption process
-----------------
Methods that intentionally skip the POST dispatcher go in the
``EXEMPT_UNWRAPPED_POST_METHODS`` allowlist below (currently line
339 — the set ships empty). See the comment block above that
declaration for the full template — Method / Issue link /
Justification / Sunset condition / Reviewer — required for every
new entry (issue #152). Write-path exemptions are expected to be
rare because order-submission paths have idempotency concerns.
"""
import ast
from pathlib import Path
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the #148 cancel_order test module)
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


# Parametrization helper: drives every error-mapping test across all 5 POST
# sites. Each entry is (site_label, invoker_fn). The invoker patches the
# minimum surface needed to reach ``self.post(...)`` and then triggers it
# with the site-specific fake that raises the given ``HTTPError``.


def _invoke_submit_sell_order(rh, http_err):
    """Drive ``submit_sell_order`` to its ``self.post`` site."""
    fake_quote = {"bid_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_quote", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.submit_sell_order(
            instrument_url="https://api.robinhood.com/instruments/XYZ/",
            symbol="XYZ",
            order_type="market",
            time_in_force="gfd",
            trigger="immediate",
            quantity=1,
            side="sell",
        )


def _invoke_submit_buy_order(rh, http_err):
    """Drive ``submit_buy_order`` to its ``self.post`` site."""
    fake_quote = {"ask_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_quote", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.submit_buy_order(
            instrument_url="https://api.robinhood.com/instruments/XYZ/",
            symbol="XYZ",
            order_type="market",
            time_in_force="gfd",
            trigger="immediate",
            quantity=1,
            side="buy",
        )


def _invoke_place_order(rh, http_err):
    """Drive ``place_order`` to its ``self.post`` site."""
    fake_quote = {"bid_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    from pyrh.robinhood import Transaction

    with patch("pyrh.robinhood.Robinhood.quote_data", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.place_order(
            instrument={
                "url": "https://api.robinhood.com/instruments/XYZ/",
                "symbol": "XYZ",
            },
            quantity=1,
            price=10.0,
            transaction=Transaction.BUY,
            trigger="immediate",
            order="market",
            time_in_force="gfd",
        )


def _invoke_cancel_order_str_branch_post(rh, http_err):
    """Drive ``cancel_order`` str-branch to its inner ``self.post`` retry site.

    The outer ``self.post(order["cancel"])`` sits inside a try/except that
    retries on HTTPError, then the inner retry raises the ValueError that
    this PR replaces with the dispatcher. To reach the inner site, make
    BOTH posts raise (the outer is swallowed by its own except, the inner
    is what escapes).
    """
    fake_order = {"cancel": "https://api.robinhood.com/orders/abc/cancel/"}

    def fake_get_url(self, *args, **kwargs):
        return fake_order

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.cancel_order("abc-123-order-id")


def _invoke_cancel_order_dict_branch_post(rh, http_err):
    """Drive ``cancel_order`` dict-branch to its inner ``self.post`` retry site."""
    fake_order = {"cancel": "https://api.robinhood.com/orders/abc/cancel/"}

    def fake_get_url(self, *args, **kwargs):
        return fake_order

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.cancel_order({"id": "abc-123-order-id"})


POST_SITES = [
    ("submit_sell_order", _invoke_submit_sell_order),
    ("submit_buy_order", _invoke_submit_buy_order),
    ("place_order", _invoke_place_order),
    ("cancel_order_str_branch", _invoke_cancel_order_str_branch_post),
    ("cancel_order_dict_branch", _invoke_cancel_order_dict_branch_post),
]


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError    (4 statuses x 5 sites = 20 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_post_methods_5xx_raises_RobinhoodServerError(site_label, invoke, status):
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodServerError) as exc_info:
        invoke(rh, _http_error(status))

    # The bug being fixed: previously raised ValueError (cancel_order POST
    # sites) or leaked raw HTTPError (submit/place order POST sites).
    assert not isinstance(exc_info.value, ValueError)
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4xx  ->  RobinhoodOrderSubmissionError    (3 statuses x 5 sites = 15 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
@pytest.mark.parametrize("status", [400, 403, 404])
def test_post_methods_4xx_raises_RobinhoodOrderSubmissionError(
    site_label, invoke, status
):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        invoke(rh, _http_error(status))

    # Must NOT be plain ValueError — that's the legacy contract this PR
    # breaks (for cancel_order POST sites) and establishes (for submit/place).
    assert not isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with + without Retry-After x 5 = 10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_429_with_retry_after(site_label, invoke):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        invoke(rh, _http_error(429, headers={"Retry-After": "17"}))

    assert not isinstance(exc_info.value, ValueError)
    assert getattr(exc_info.value, "retry_after", None) == 17


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_429_without_retry_after(site_label, invoke):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        invoke(rh, _http_error(429))

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  RobinhoodOrderSubmissionError  (5 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_no_response_raises_fallback(site_label, invoke):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        invoke(rh, requests.exceptions.HTTPError("boom -- no response attached"))

    assert not isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# Surface-scan AST guard (twin of the get_url guard in
# ``test_robinhood_phase_c_and_142_http_error_mapping.py``).
# ---------------------------------------------------------------------------


# Methods on ``Robinhood`` that are intentionally NOT wrapped in a
# ``try/except requests.HTTPError`` dispatcher on their ``self.post(...)``
# call sites. Each entry requires a justification comment.
#
# Exemption process (issue #152)
# ------------------------------
# Adding an entry here bypasses the POST surface-scan guard. Reviewers
# cannot approve an exemption without knowing WHY it is safe and WHEN it
# should be re-audited. Every new entry MUST carry a block comment
# immediately above (or inline after) the string literal with all five
# template fields:
#
#     # Method: <method_name_as_string_literal>
#     # Issue link: <github issue URL documenting the exemption, or N/A>
#     # Justification: <why this POST call site does NOT need the
#     #   dispatcher; note that order-submission paths have idempotency
#     #   concerns — see ``RobinhoodOrderSubmissionError`` docstring —
#     #   so exemptions on write paths should be rare and well-argued>
#     # Sunset condition: <under what future change does this exemption
#     #   lapse; e.g. "when issue #X introduces a shared seam for this
#     #   method family">
#     # Reviewer: <name + YYYY-MM-DD when the exemption was approved>
#
# Example entry (active) — none today; the allowlist is intentionally
# empty so every ``self.post(...)`` call site dispatches via
# ``_raise_for_http_error``. When the first exemption is added, it MUST
# follow the template above. For reference, the GET-path twin allowlist
# in ``test_robinhood_phase_c_and_142_http_error_mapping.py`` has a
# worked example (the ``get_url`` self-reference seam).
#
# The meta-test ``test_exempt_post_allowlist_has_exemption_process_documented``
# asserts that each template field string is present in this declaration
# block, so removing the fields breaks the suite.
EXEMPT_UNWRAPPED_POST_METHODS: frozenset = frozenset()


def test_no_unwrapped_self_post_call_sites_on_robinhood_class():
    """Surface scan: no ``Robinhood`` method may call ``self.post(...)``
    outside a ``try`` block whose handler dispatches via
    ``_raise_for_http_error`` unless explicitly allowlisted.

    Twin of ``test_no_unwrapped_get_url_call_sites_on_robinhood_class``
    from the #142/#144 surface-scan guard, extended to the write path.
    Every ``self.post(...)`` call site must live inside a ``try`` block
    whose handler invokes ``_raise_for_http_error(...,
    fallback_exc=RobinhoodOrderSubmissionError)`` OR the method name
    must be added to ``EXEMPT_UNWRAPPED_POST_METHODS`` with a
    justification.

    Issue #144 round-2 tightened this from the loose ``_inside_try +
    has_dispatcher`` shape (originally introduced in PR #14 / #147)
    to the same ``_inside_try_with_dispatcher`` semantic used by the
    ``get_url`` guard — the enclosing try's handler must actually
    dispatch, not merely exist. Helpers now live in
    ``tests/_ast_guard_helpers.py`` and are shared across both guards.
    """
    from tests._ast_guard_helpers import (
        _inside_try_with_dispatcher,
        _is_self_post_call,
    )

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

    offenders = []
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in EXEMPT_UNWRAPPED_POST_METHODS:
            continue
        for node in ast.walk(method):
            if not _is_self_post_call(node):
                continue
            if _inside_try_with_dispatcher(method, node):
                continue
            offenders.append((method.name, node.lineno))

    if offenders:
        formatted = "\n".join(
            f"  - {name} at line {lineno}" for name, lineno in offenders
        )
        pytest.fail(
            "Unwrapped self.post(...) call sites found on Robinhood class "
            "(issue #147 POST-path dispatcher + #144 round-2 tightening):\n"
            f"{formatted}\n\n"
            "Each call site must either be inside a ``try/except "
            "requests.HTTPError`` block that invokes "
            "``_raise_for_http_error(e, fallback_exc=RobinhoodOrderSubmissionError)``, "
            "or the method name must be added to "
            "``EXEMPT_UNWRAPPED_POST_METHODS`` above with a "
            "justification comment explaining why it is intentionally "
            "unwrapped."
        )


# ---------------------------------------------------------------------------
# Issue #144 / #147 — tighten the POST surface-scan AST guard.
#
# PR #14 (#147) landed the POST-path dispatcher and a twin surface-scan
# guard that reuses the same loose ``_inside_try`` logic as the pre-PR
# #13 ``get_url`` guard: the guard only verifies that the ``self.post``
# call is a DESCENDANT of some ``ast.Try`` node, not that the matching
# except handler actually invokes ``_raise_for_http_error``.
#
# The same-shape weakness as #144 (applied to POST): a method that does
#
#     try:
#         self.post(urls.orders(), data=payload)
#     except requests.HTTPError:
#         raise ValueError("bad order")
#
# passes the loose POST guard silently, even though it does NOT dispatch
# via the shared helper. Merging PR #15 (#144) without fixing this leaves
# #144 only half-closed — the GET surface is tight but POST is still loose.
#
# These tests pin the TIGHT semantic for POST: the guard must verify at
# least one except handler in the enclosing try calls
# ``_raise_for_http_error``. Helpers are imported from
# ``tests._ast_guard_helpers`` so they share one implementation with the
# ``get_url`` guard (parameterized on method name).
# ---------------------------------------------------------------------------


def _parse_single_method_with_post(source: str):
    """Parse a dedented ``def`` source and return ``(FunctionDef, post_call)``.

    Used by the #147 tightening tests to build small, readable fixtures.
    """
    import textwrap

    from tests._ast_guard_helpers import _is_self_post_call

    tree = ast.parse(textwrap.dedent(source))
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    calls = [n for n in ast.walk(method) if _is_self_post_call(n)]
    assert calls, f"Fixture must contain self.post(...): {source!r}"
    return method, calls


def test_post_guard_rejects_try_except_that_raises_unrelated_exc():
    """Tight POST guard: flags ``try: self.post(...) except HTTPError:
    raise ValueError(...)`` — the handler does NOT dispatch, so the POST
    call is effectively unwrapped. This is the same-shape weakness as
    pre-PR #13 ``cancel_order`` applied to the POST write path.
    """
    from tests._ast_guard_helpers import _inside_try_with_dispatcher

    method, calls = _parse_single_method_with_post(
        """
        def submit_buy_order_like(self, payload):
            try:
                return self.post(urls.orders(), data=payload)
            except requests.exceptions.HTTPError:
                raise ValueError("bad order submission")
        """
    )

    # Tight semantic: try exists and wraps the post call, but the except
    # handler does not dispatch via ``_raise_for_http_error`` -> NOT covered.
    assert _inside_try_with_dispatcher(method, calls[0]) is False


def test_post_guard_accepts_proper_dispatcher_wrap():
    """Tight POST guard: accepts the exact shape used by the wrapped
    POST methods (``submit_buy_order``, ``submit_sell_order``,
    ``place_order``, and the inner retry in ``cancel_order``).
    """
    from tests._ast_guard_helpers import _inside_try_with_dispatcher

    method, calls = _parse_single_method_with_post(
        """
        def submit_buy_order_like(self, payload):
            try:
                return self.post(urls.orders(), data=payload)
            except requests.exceptions.HTTPError as e:
                _raise_for_http_error(e, fallback_exc=RobinhoodOrderSubmissionError)
        """
    )

    assert _inside_try_with_dispatcher(method, calls[0]) is True


def test_post_guard_cancel_order_nested_retry_shape_documented():
    """``cancel_order`` POST shape: outer post with retry-on-HTTPError,
    inner retry dispatcher-wrapped.

    Shape:

        try:
            res = self.post(order["cancel"])   # OUTER
            return res
        except requests.HTTPError:
            try:
                res = self.post(order["cancel"])   # INNER (retry)
                return res
            except requests.HTTPError as e:
                _raise_for_http_error(e, fallback_exc=...)

    Current tight-guard semantics (``_handler_calls_dispatcher`` does
    ``ast.walk(handler)``) classify BOTH posts as dispatcher-wrapped,
    because the outer handler's subtree contains the inner handler's
    ``_raise_for_http_error`` call. This is a known looseness: a
    handler that contains a nested try whose handler dispatches is
    treated as itself dispatching, even though the outer exception
    path (retry-success or retry-failure-of-a-different-class) does
    not dispatch the original exception.

    Pinning the current semantics here so the follow-up tightening
    (tracked under the Phase A/B/discovery/options consolidation, which
    also addresses the even-weaker ``isinstance(n, ast.Try)`` guards)
    has a reviewer-visible record of what "tight" means today.
    """
    from tests._ast_guard_helpers import (
        _inside_try_with_dispatcher,
        _is_self_post_call,
    )

    method, calls = _parse_single_method_with_post(
        """
        def cancel_order_like(self, order_id):
            order = self.get_url(urls.orders(order_id))
            try:
                res = self.post(order["cancel"])
                return res
            except requests.exceptions.HTTPError:
                try:
                    res = self.post(order["cancel"])
                    return res
                except requests.exceptions.HTTPError as e:
                    _raise_for_http_error(e, fallback_exc=RobinhoodOrderSubmissionError)
        """
    )

    assert len(calls) == 2
    outer_post, inner_post = sorted(calls, key=lambda n: n.lineno)

    # Inner post: enclosing try's handler dispatches directly -> ACCEPT.
    assert _inside_try_with_dispatcher(method, inner_post) is True
    # Outer post: enclosing try's handler contains a nested try whose
    # handler dispatches. Current semantics accept this (ast.walk crosses
    # the nested try boundary). Documented as known looseness — see
    # follow-up issue for the stricter "handler-own-body-only" rule.
    assert _inside_try_with_dispatcher(method, outer_post) is True


def test_post_guard_rejects_bare_try_no_handler_dispatch():
    """Edge case: ``try/except Exception: pass`` — silent swallow. Tight
    guard must reject even though a Try exists.
    """
    from tests._ast_guard_helpers import _inside_try_with_dispatcher

    method, calls = _parse_single_method_with_post(
        """
        def silent_swallow_post(self, payload):
            try:
                return self.post("/x", data=payload)
            except Exception:
                pass
        """
    )

    assert _inside_try_with_dispatcher(method, calls[0]) is False


def test_post_guard_mutation_catches_unwrapped_submit_buy_order():
    """Mutation test: rewrite the in-memory AST of ``submit_buy_order``
    to strip its ``_raise_for_http_error`` dispatch (replacing the
    handler body with ``raise ValueError(...)`` — the pre-#147 shape).
    The TIGHT guard must flag this as unwrapped; the LOOSE guard used
    by PR #14 would pass it silently because the call is still a
    descendant of an ast.Try.

    This proves the extended #144 tightening actually catches the
    POST-path regression-shape, not merely that it accepts current code.
    The comparison against the old loose semantic (``_loose_inside_try``
    defined inline below) is the regression safety net — if someone
    accidentally routes the POST guard back through the loose helper,
    this test fails.
    """
    from pathlib import Path
    import textwrap

    from tests._ast_guard_helpers import (
        _inside_try_with_dispatcher,
        _is_self_post_call,
    )

    # Replica of the pre-#144 loose helper for the comparison leg.
    def _loose_inside_try(method: ast.FunctionDef, target: ast.Call) -> bool:
        for node in ast.walk(method):
            if isinstance(node, ast.Try):
                for child in ast.walk(node):
                    if child is target:
                        return True
        return False

    # Load the real source and find ``submit_buy_order``.
    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )
    tree = ast.parse(source)

    submit_buy_order = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "submit_buy_order":
            submit_buy_order = node
            break
    assert submit_buy_order is not None, (
        "submit_buy_order not found on Robinhood class — has it been renamed?"
    )

    # Sanity: currently the guard PASSES (submit_buy_order is properly wrapped).
    post_calls = [n for n in ast.walk(submit_buy_order) if _is_self_post_call(n)]
    assert len(post_calls) == 1, (
        "submit_buy_order should have exactly one self.post(...) call site"
    )
    assert _inside_try_with_dispatcher(submit_buy_order, post_calls[0]) is True, (
        "baseline: submit_buy_order's post call should be dispatcher-wrapped"
    )

    # Mutate: replace the except handler body with ``raise ValueError(...)``
    # (the pre-#147 shape). Find the enclosing Try, rewrite.
    def _find_enclosing_try(method, call):
        for try_node in ast.walk(method):
            if not isinstance(try_node, ast.Try):
                continue
            for stmt in try_node.body:
                for descendant in ast.walk(stmt):
                    if descendant is call:
                        return try_node
        return None

    enclosing_try = _find_enclosing_try(submit_buy_order, post_calls[0])
    assert enclosing_try is not None, "post call must have an enclosing Try"

    # Replace each handler's body with ``raise ValueError("bad order")`` — a
    # clear non-dispatching shape.
    mutant_body = ast.parse(
        textwrap.dedent(
            """
            raise ValueError("bad order")
            """
        )
    ).body
    for handler in enclosing_try.handlers:
        handler.body = mutant_body

    # LOOSE guard: the call is still a descendant of an ast.Try, so the
    # loose helper would pass it silently. This demonstrates the regression
    # that the tight guard catches.
    assert _loose_inside_try(submit_buy_order, post_calls[0]) is True, (
        "loose helper should still see the call as 'inside a try' — "
        "that is the weakness the tight guard fixes"
    )

    # TIGHT guard: the mutated handler does not call _raise_for_http_error,
    # so the call is effectively unwrapped -> guard must REJECT.
    assert _inside_try_with_dispatcher(submit_buy_order, post_calls[0]) is False, (
        "tight POST guard must flag submit_buy_order as unwrapped when its "
        "except handler raises ValueError instead of dispatching"
    )


def test_post_guard_flags_mutated_submit_buy_order_that_drops_dispatcher():
    """End-to-end guard test: mutate ``submit_buy_order`` in-memory to
    drop its ``_raise_for_http_error`` call (replaced with
    ``raise ValueError``), then re-run the surface-scan logic. The
    guard MUST flag ``submit_buy_order`` as an offender.

    This is the real regression-catching test: it exercises the same
    code path as the top-level surface scan
    (``test_no_unwrapped_self_post_call_sites_on_robinhood_class``) on
    a mutated AST, proving the scan would have caught PR #14's
    regression shape. Under the LOOSE ``_inside_try`` (any-Try ancestor)
    this test would not catch the mutation, because the post call is
    still inside an ast.Try — hence the guard had to be tightened.
    """
    from pathlib import Path
    import textwrap

    from tests._ast_guard_helpers import (
        _inside_try_with_dispatcher,
        _is_self_post_call,
    )

    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )
    tree = ast.parse(source)
    robinhood_class = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
    )

    submit_buy_order = next(
        m
        for m in ast.walk(robinhood_class)
        if isinstance(m, ast.FunctionDef) and m.name == "submit_buy_order"
    )

    # Locate the enclosing try wrapping the real post call and mutate
    # its handler to raise ValueError (pre-#147 shape).
    post_calls = [n for n in ast.walk(submit_buy_order) if _is_self_post_call(n)]
    assert len(post_calls) == 1

    def _find_enclosing_try(method, call):
        for try_node in ast.walk(method):
            if not isinstance(try_node, ast.Try):
                continue
            for stmt in try_node.body:
                for descendant in ast.walk(stmt):
                    if descendant is call:
                        return try_node
        return None

    enclosing_try = _find_enclosing_try(submit_buy_order, post_calls[0])
    mutant_body = ast.parse(
        textwrap.dedent('raise ValueError("bad order")')
    ).body
    for handler in enclosing_try.handlers:
        handler.body = mutant_body

    # Re-run the SAME surface-scan logic as the top-level guard, using
    # the shared tight helpers. Expect submit_buy_order to surface as
    # an offender.
    offenders = []
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in EXEMPT_UNWRAPPED_POST_METHODS:
            continue
        for node in ast.walk(method):
            if not _is_self_post_call(node):
                continue
            if _inside_try_with_dispatcher(method, node):
                continue
            offenders.append((method.name, node.lineno))

    offender_names = {name for name, _ in offenders}
    assert "submit_buy_order" in offender_names, (
        "tight POST guard must flag submit_buy_order after its dispatcher "
        "call is mutated to a raise ValueError. offenders="
        f"{sorted(offender_names)}"
    )


def test_post_guard_tight_scan_passes_on_real_module():
    """Integration: running the tight surface scan on the real
    ``robinhood.py`` must not flag any method. Every ``self.post(...)``
    call site is either dispatcher-wrapped directly (``submit_buy_order``,
    ``submit_sell_order``, ``place_order``, inner ``cancel_order`` retry)
    or sits in the ``cancel_order`` outer-retry shape documented in
    ``test_post_guard_cancel_order_nested_retry_shape_documented`` above.

    This test is the POST-path twin of
    ``test_tightened_guard_passes_on_real_robinhood_module`` in the
    ``get_url`` guard module. It re-runs the full class scan via the
    TIGHT helpers so any future method that slips in with the #144
    loose-try-without-dispatch shape is caught.
    """
    from pathlib import Path

    from tests._ast_guard_helpers import (
        _inside_try_with_dispatcher,
        _is_self_post_call,
    )

    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )
    tree = ast.parse(source)
    robinhood_class = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
    )

    offenders = []
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in EXEMPT_UNWRAPPED_POST_METHODS:
            continue
        for node in ast.walk(method):
            if not _is_self_post_call(node):
                continue
            if _inside_try_with_dispatcher(method, node):
                continue
            offenders.append((method.name, node.lineno))

    assert offenders == [], (
        "Tight POST surface scan flagged methods. Each entry indicates a "
        "method that calls self.post(...) with no enclosing try whose "
        "handler dispatches via _raise_for_http_error — i.e. an unwrapped "
        "POST call site:\n"
        + "\n".join(f"  - {name} at line {lineno}" for name, lineno in offenders)
    )


# ---------------------------------------------------------------------------
# Issue #152 — document the exemption process for
# ``EXEMPT_UNWRAPPED_POST_METHODS``.
#
# Twin of the #149 meta-test in the GET-path module. The POST allowlist
# currently ships empty, but the template header must already be present
# so the first contributor who needs an exemption has a shape to follow.
# ---------------------------------------------------------------------------


def test_exempt_post_allowlist_has_exemption_process_documented():
    """Ensure ``EXEMPT_UNWRAPPED_POST_METHODS`` declaration has the
    expected template fields documented in comments.

    The template (see #152) is:

        # Method: <name>
        # Issue link: <github issue URL or N/A>
        # Justification: <why this method does NOT need the dispatcher>
        # Sunset condition: <when should this be re-added to coverage>
        # Reviewer: <name + date>

    Prevents future drift where an exempt entry is added without the
    justification fields a reviewer needs to approve the exemption.
    The check is scoped to the block that starts at the allowlist
    declaration and ends at the next top-level ``def`` / ``class`` /
    ``# ---`` section break, so the template must live adjacent to the
    allowlist itself (not elsewhere in the file).
    """
    lines = Path(__file__).read_text().splitlines()
    decl = next(
        (
            i
            for i, line in enumerate(lines)
            if line.startswith("EXEMPT_UNWRAPPED_POST_METHODS")
        ),
        None,
    )
    assert decl is not None, "Allowlist declaration not found in this file."
    # Walk backward to the nearest section-break (``# ---``) and forward
    # to the next top-level ``def`` / ``class`` / section break.
    start = 0
    for i in range(decl - 1, -1, -1):
        if lines[i].startswith("# ---"):
            start = i
            break
    end = len(lines)
    for i in range(decl + 1, len(lines)):
        line = lines[i]
        if line.startswith(("def ", "class ", "# ---")):
            end = i
            break
    region = "\n".join(lines[start:end])
    for field in (
        "# Method:",
        "# Issue link:",
        "# Justification:",
        "# Sunset condition:",
        "# Reviewer:",
    ):
        assert field in region, (
            f"EXEMPT_UNWRAPPED_POST_METHODS template field {field!r} "
            "missing from the allowlist declaration block. Each exempt "
            "entry must follow the template documented adjacent to the "
            "allowlist (issue #152)."
        )
