# coding=utf-8
"""Shared AST helpers for surface-scan guards (``get_url`` + ``post`` paths).

History
-------
Issue #144 tightened the ``get_url`` surface-scan guard in
``tests/test_robinhood_phase_c_and_142_http_error_mapping.py`` by replacing
the loose ``_inside_try`` (any ast.Try ancestor) with
``_inside_try_with_dispatcher`` (nearest enclosing Try's handlers must
invoke ``_raise_for_http_error``). While merging that work, review found
that PR #14 (#147) had introduced a twin surface-scan guard for POST
paths with the SAME loose-try weakness. This module extracted the tight
helpers so BOTH guards share one implementation.

Issues #141 / #158 extended the consolidation to the remaining three
method-list guards (Phase A, Phase B, options). Those each carried their
own ``_has_dispatcher`` returning True on ANY ``ast.Try`` anywhere in
the method body — worse than the loose ``_inside_try`` that #144 fixed
(it did not even require the call to be inside the try). They now all
route through ``_inside_try_with_dispatcher`` + ``_is_self_get_url_call``.

Design
------
The helpers are parameterized on the method name being matched
(``get_url`` or ``post``) rather than duplicated per call-matcher.
``_is_self_method_call`` is the generic primitive; the named wrappers
(``_is_self_get_url_call``, ``_is_self_post_call``) are thin aliases so
call sites read cleanly.

Scope
-----
Used by 5 guards (consolidation complete as of #141 / #158):

* ``tests/test_robinhood_phase_c_and_142_http_error_mapping.py`` —
  ``test_no_unwrapped_get_url_call_sites_on_robinhood_class`` (#142 / #144,
  surface-scan over every ``Robinhood`` method with an exemption
  allowlist).
* ``tests/test_robinhood_post_path_order_submission_http_error_mapping.py`` —
  ``test_no_unwrapped_self_post_call_sites_on_robinhood_class`` (#147,
  POST-path twin; tightened via this module in #144).
* ``tests/test_robinhood_trading_portfolio_http_error_mapping.py`` —
  ``test_all_phase_a_methods_have_http_error_handling`` (#137 Phase A;
  tightened here in #141 / #158).
* ``tests/test_robinhood_discovery_http_error_mapping.py`` —
  ``test_all_phase_b_methods_have_http_error_handling`` (#137 Phase B;
  tightened here in #141 / #158).
* ``tests/test_robinhood_options_methods_http_error_mapping.py`` —
  ``test_all_options_methods_have_http_error_handling`` (#135; tightened
  here in #141 / #158).

Known limitations (out-of-scope, tracked separately):

* ``_inside_try_with_dispatcher`` uses ``ast.walk(handler)`` to find
  ``_raise_for_http_error`` — a nested try whose handler swallows the
  call and raises unrelated would still pass if an OUTER handler
  contains a ``_raise_for_http_error`` call. This is a narrow blind
  spot acknowledged in #144 and deferred.
"""
from __future__ import annotations

import ast


def _is_self_method_call(node: ast.AST, method_name: str) -> bool:
    """True iff ``node`` is ``self.<method_name>(...)``.

    Matches the call-shape used across the ``Robinhood`` class for HTTP
    surface methods. Rejects attribute calls where ``self`` is not the
    direct receiver (e.g. ``self.session.post(...)``), matching the
    intent of the surface scan — we only want to scope this guard to
    the class's own ``get_url``/``post`` wrappers, not third-party HTTP
    clients used internally.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr != method_name:
        return False
    value = func.value
    if not isinstance(value, ast.Name):
        return False
    return value.id == "self"


def _is_self_get_url_call(node: ast.AST) -> bool:
    """Alias: ``self.get_url(...)``. Used by the #142/#144 guard."""
    return _is_self_method_call(node, "get_url")


def _is_self_post_call(node: ast.AST) -> bool:
    """Alias: ``self.post(...)``. Used by the #147 guard."""
    return _is_self_method_call(node, "post")


def _handler_calls_dispatcher(handler: ast.ExceptHandler) -> bool:
    """True iff ``except`` handler body invokes ``_raise_for_http_error``.

    Accepts both bare-name (``_raise_for_http_error(e)``) and attribute
    forms (``self._raise_for_http_error(e)`` /
    ``pyrh.robinhood._raise_for_http_error(e)``) — anything whose
    call target's trailing segment is ``_raise_for_http_error``.
    """
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "_raise_for_http_error":
            return True
        if isinstance(fn, ast.Attribute) and fn.attr == "_raise_for_http_error":
            return True
    return False


def _inside_try_with_dispatcher(method: ast.FunctionDef, target: ast.Call) -> bool:
    """True iff ``target`` is in the body of some ``ast.Try`` inside
    ``method`` AND at least one of that Try's except handlers invokes
    ``_raise_for_http_error``.

    Walks Try nodes in the method; for each, checks whether ``target``
    is a descendant of the Try's body (not its handlers / else /
    finalbody — those are NOT protected by the dispatcher). If the body
    contains the call, the handlers must dispatch for the result to be
    True. Nested try/except is supported: any enclosing try whose
    handlers dispatch counts as covered.

    Tightening rationale (#144): the prior ``_inside_try`` helper only
    checked Try ancestry (any ast.Try containing the call anywhere
    inside), which let through methods whose except handler did NOT
    dispatch — e.g. ``try: self.get_url(...) except HTTPError: raise
    ValueError(...)``. That is the same-shape weakness as #136.

    The POST-path twin (#147) had the same looseness before this module
    consolidated the helpers; now both guards call through here.
    """

    def _body_contains(try_node: ast.Try, call: ast.Call) -> bool:
        # Walk only the ``try`` body (protected region), not handlers /
        # else / finalbody. A call inside an except handler is NOT
        # covered by the dispatcher for THAT try.
        for stmt in try_node.body:
            for descendant in ast.walk(stmt):
                if descendant is call:
                    return True
        return False

    for try_node in ast.walk(method):
        if not isinstance(try_node, ast.Try):
            continue
        if not _body_contains(try_node, target):
            continue
        for handler in try_node.handlers:
            if _handler_calls_dispatcher(handler):
                return True
        # Call is in this try's body but no handler dispatches. Keep
        # walking in case an OUTER try (nested) dispatches.
    return False
