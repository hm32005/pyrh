# coding=utf-8
"""Issue #136 — AST guard must verify try/except ENCLOSES the HTTP call.

Issue #136 flagged a gap in the options-surface AST symmetry guard:
a future method shaped like

    def get_option_foo(self):
        try:
            x = 1
        except Exception:
            pass
        return self.get_url(...)  # UNWRAPPED, OUTSIDE the try

would pass a loose guard (any ast.Try + any _raise_for_http_error Name
node) while still leaking raw ``requests.HTTPError`` to the caller —
the try is a decoy that doesn't enclose the HTTP call.

PR #17 (#141 / #158) already tightened the guard via
``tests/_ast_guard_helpers._inside_try_with_dispatcher``, which walks
only ``Try.body`` (not the whole method) when searching for the HTTP
call. This module pins the specific #136 contract at the helper level
so a future refactor that regresses the tightening (e.g. replaces
``_body_contains`` with ``ast.walk(method)``) fails loudly with a test
name that references #136 directly.

Covers four shapes:

    1. Decoy try + unwrapped call after     → offender (the #136 scenario).
    2. Try enclosing the call + dispatcher  → OK (negative control).
    3. Try enclosing the call + non-dispatcher handler → offender.
    4. Call inside except handler (not body) → offender (the try body does
       NOT enclose the call — ``except`` bodies are sibling regions).
"""
import ast

from tests._ast_guard_helpers import (
    _inside_try_with_dispatcher,
    _is_self_get_url_call,
)


def _parse_method(src):
    """Parse ``src`` and return its first ``ast.FunctionDef`` node."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no FunctionDef in source")


def _get_url_call(method):
    for node in ast.walk(method):
        if _is_self_get_url_call(node):
            return node
    raise AssertionError("no self.get_url(...) call in method")


# ---------------------------------------------------------------------------
# Scenario 1 — the exact #136 regression shape.
# ---------------------------------------------------------------------------


def test_issue_136_decoy_try_before_unwrapped_get_url_not_inside_dispatcher():
    """#136 regression shape: try exists but does NOT enclose the HTTP call.

    This is the precise scenario quoted in issue #136. The loose predicate
    (any ast.Try in the function) would accept this method; the tight
    helper must reject because ``self.get_url`` is NOT a descendant of the
    try's body.
    """
    src = """
def get_option_foo(self):
    try:
        x = 1
    except Exception:
        pass
    return self.get_url("/marketdata/options/xyz")
"""
    method = _parse_method(src)
    call = _get_url_call(method)

    assert _inside_try_with_dispatcher(method, call) is False, (
        "Tight helper regressed: a decoy try/except that does NOT enclose "
        "the HTTP call must not count as dispatcher coverage (#136)."
    )


def test_issue_136_decoy_try_with_dispatcher_somewhere_else_still_rejected():
    """Stricter #136 variant: the method has a decoy try-except AND a
    separate ``_raise_for_http_error`` call ELSEWHERE (e.g. a dead branch
    or a different control flow). The historically-loose predicate
    (``any ast.Try OR any _raise_for_http_error Name node``) would
    accept this method; the tight helper must still reject because the
    dispatcher call is not attached to the try that encloses ``self.get_url``.

    This variant is what makes the #136 fix non-trivial — without it
    ``ast.walk(method)`` anywhere in the function body is enough to
    satisfy a loose guard.
    """
    src = """
def get_option_hybrid(self, other_arg):
    try:
        x = 1
    except Exception:
        pass
    if other_arg:
        # Dispatcher call on an unrelated branch — decoy for the loose predicate.
        _raise_for_http_error(None)
    return self.get_url("/marketdata/options/xyz")
"""
    method = _parse_method(src)
    call = _get_url_call(method)

    assert _inside_try_with_dispatcher(method, call) is False, (
        "Tight helper regressed: dispatcher call ELSEWHERE in the method "
        "must not credit an unrelated try with covering the HTTP call (#136)."
    )


# ---------------------------------------------------------------------------
# Scenario 2 — proper wrap (negative control).
# ---------------------------------------------------------------------------


def test_proper_try_enclosing_get_url_with_dispatcher_handler_accepted():
    """Sanity: the correct shape must still be accepted."""
    src = """
def get_option_bar(self, option_id):
    try:
        return self.get_url("/marketdata/options/" + option_id)
    except requests.exceptions.HTTPError as e:
        _raise_for_http_error(e, fallback_exc=InvalidOptionId)
"""
    method = _parse_method(src)
    call = _get_url_call(method)

    assert _inside_try_with_dispatcher(method, call) is True


# ---------------------------------------------------------------------------
# Scenario 3 — try wraps call but handler does not dispatch (#144 shape).
# ---------------------------------------------------------------------------


def test_try_encloses_call_but_handler_does_not_dispatch_is_rejected():
    """Complementary gap: try WRAPS the call but handler raises ValueError
    instead of calling ``_raise_for_http_error``. This is what #144 fixed;
    pinning it here alongside #136 keeps both gaps covered by name.
    """
    src = """
def get_option_baz(self, option_id):
    try:
        return self.get_url("/marketdata/options/" + option_id)
    except requests.exceptions.HTTPError:
        raise ValueError("bad option")
"""
    method = _parse_method(src)
    call = _get_url_call(method)

    assert _inside_try_with_dispatcher(method, call) is False


# ---------------------------------------------------------------------------
# Scenario 4 — call inside an except handler (not the try body).
# ---------------------------------------------------------------------------


def test_get_url_inside_except_handler_is_not_body_enclosed():
    """Edge case: the HTTP call lives INSIDE an ``except`` handler (e.g.
    a retry after a different exception). That call site is NOT protected
    by the dispatcher attached to THIS try — the except body is a sibling
    region, not the protected body.

    Behaviour of ``_inside_try_with_dispatcher`` today: walks only
    ``Try.body``; if the call is in a handler and no OUTER try encloses
    it, the helper returns False.
    """
    src = """
def get_option_retry(self, option_id):
    try:
        raise RuntimeError("kick us into the except")
    except RuntimeError:
        return self.get_url("/marketdata/options/" + option_id)
"""
    method = _parse_method(src)
    call = _get_url_call(method)

    assert _inside_try_with_dispatcher(method, call) is False, (
        "Call inside an except handler is not covered by THAT try's "
        "dispatcher — the protected region is only ``Try.body``."
    )
