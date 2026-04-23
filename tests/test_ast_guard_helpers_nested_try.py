# coding=utf-8
"""Regression guard for ``_handler_calls_dispatcher`` nested-try tightening
(issue #162).

Problem
-------
Prior to #162, ``_handler_calls_dispatcher`` in
``tests/_ast_guard_helpers.py`` used ``ast.walk(handler)`` to locate calls
to ``_raise_for_http_error``. ``ast.walk`` recurses into every descendant,
including nested ``ast.Try`` nodes — so an outer ``except`` handler that
contained a nested ``try`` whose INNER handler dispatched was treated as
if the OUTER handler itself dispatched.

This gave the POST-path surface-scan guard a blind spot: the outer
``self.post(...)`` call in ``cancel_order``'s retry shape was credited
with being dispatcher-wrapped even though its outer handler does NOT call
``_raise_for_http_error`` directly — the call lives inside a nested try
under that handler. See ``test_post_guard_cancel_order_nested_retry_shape_documented``
in ``test_robinhood_post_path_order_submission_http_error_mapping.py`` for
the original "known looseness" pin.

Fix
---
Replace ``ast.walk(handler)`` with a manual walker that treats
``ast.Try`` subtrees as opaque — a handler "directly dispatches" only if
its own body (including descendants OTHER than nested Try nodes) contains
the call. Nested try/except has its own handlers; the outer handler
doesn't get credit for what the inner handler does.

Consequence
-----------
After the tightening, ``cancel_order``'s outer ``self.post(order["cancel"])``
call site legitimately surfaces as an offender in the POST surface scan.
That outer call is intentionally retry-wrapped (not dispatcher-wrapped),
so ``cancel_order`` is added to the POST allowlist with a full
justification block per the #152 exemption template.
"""
from __future__ import annotations

import ast
import textwrap


# ---------------------------------------------------------------------------
# RED: nested-try boundary must NOT be crossed by _handler_calls_dispatcher
# ---------------------------------------------------------------------------


def test_handler_calls_dispatcher_rejects_nested_try_dispatch():
    """A handler whose body contains a nested try WHOSE inner handler dispatches
    must NOT be treated as itself dispatching.

    Shape under test (same as ``cancel_order``'s outer retry):

        try:
            self.post(...)                    # OUTER try body
        except requests.HTTPError:            # OUTER handler
            try:
                self.post(...)                # INNER try body
            except requests.HTTPError as e:
                _raise_for_http_error(e, ...) # INNER handler dispatches

    The OUTER handler itself contains NO ``_raise_for_http_error`` call.
    Tight helper: returns ``False`` (outer does not directly dispatch).
    Loose helper (pre-#162 ``ast.walk``): returns ``True`` (finds the inner
    dispatch) — the bug being fixed.
    """
    from tests._ast_guard_helpers import _handler_calls_dispatcher

    source = textwrap.dedent(
        """
        def cancel_order_like(self, order_id):
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
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    # The FunctionDef body is [Try] — outer try at index 0.
    outer_try = func.body[0]
    assert isinstance(outer_try, ast.Try), "Fixture: expected outer try at body[0]"
    outer_handler = outer_try.handlers[0]

    assert _handler_calls_dispatcher(outer_handler) is False, (
        "Tight _handler_calls_dispatcher must not cross nested-try "
        "boundaries — the outer handler's subtree contains a nested try "
        "whose inner handler dispatches, but the OUTER handler itself "
        "does not call _raise_for_http_error."
    )


def test_handler_calls_dispatcher_accepts_direct_dispatch():
    """Baseline: a handler that calls ``_raise_for_http_error`` directly
    (no nesting) is still accepted. Guards against overcorrection."""
    from tests._ast_guard_helpers import _handler_calls_dispatcher

    source = textwrap.dedent(
        """
        def straightforward(self, x):
            try:
                self.get_url(x)
            except requests.exceptions.HTTPError as e:
                _raise_for_http_error(e, fallback_exc=InvalidTickerSymbol)
        """
    )
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    handler = func.body[0].handlers[0]

    assert _handler_calls_dispatcher(handler) is True


def test_handler_calls_dispatcher_accepts_dispatch_inside_if():
    """A handler body wrapping the dispatcher in a conditional (e.g.
    ``if status_is_retryable: ... else: _raise_for_http_error(...)``) still
    counts as dispatching — the manual walker must recurse through
    ``ast.If``, ``ast.For``, etc., stopping ONLY at nested ``ast.Try``."""
    from tests._ast_guard_helpers import _handler_calls_dispatcher

    source = textwrap.dedent(
        """
        def conditional_dispatch(self, x):
            try:
                self.get_url(x)
            except requests.exceptions.HTTPError as e:
                if True:
                    _raise_for_http_error(e, fallback_exc=InvalidTickerSymbol)
        """
    )
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    handler = func.body[0].handlers[0]

    assert _handler_calls_dispatcher(handler) is True


def test_handler_calls_dispatcher_rejects_swallowing_handler():
    """A handler that silently swallows (``pass``) or re-raises an unrelated
    exception (``raise ValueError(...)``) must be rejected. Regression guard
    against the pre-#144 loose-try weakness applied at the handler level."""
    from tests._ast_guard_helpers import _handler_calls_dispatcher

    source = textwrap.dedent(
        """
        def swallow(self, x):
            try:
                self.get_url(x)
            except requests.exceptions.HTTPError:
                pass
        """
    )
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    handler = func.body[0].handlers[0]

    assert _handler_calls_dispatcher(handler) is False
