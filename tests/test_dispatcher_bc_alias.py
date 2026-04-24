# coding=utf-8
"""Backwards-compatibility pin for ``_raise_for_quote_http_error`` alias (#134).

PR #8 renamed the HTTP-error dispatcher from ``_raise_for_quote_http_error``
to ``_raise_for_http_error`` and kept the old name as a module-level
alias assignment:

    _raise_for_quote_http_error = _raise_for_http_error

The alias is an ASSIGNMENT — not a wrapper function. This means:
* External importers of the old private name keep working byte-for-byte.
* The keyword-only ``fallback_exc`` kwarg remains reachable through
  either name (no shadowing by a wrapper's signature).
* ``inspect.signature()`` gives the same result from either name.

Issue #134: pin this contract so a future refactor that replaces the
assignment with a wrapper function (e.g. to emit a ``DeprecationWarning``)
breaks this test rather than silently changing semantics.
"""


def test_quote_alias_is_identity_for_general_dispatcher():
    """The old name and the new name must be the SAME callable object.

    If someone rewrites the alias as ``def _raise_for_quote_http_error(...)``
    they will lose ``is``-identity AND may inadvertently change the
    accepted kwargs. This test fails loudly in either case.
    """
    from pyrh.robinhood import _raise_for_http_error, _raise_for_quote_http_error

    assert _raise_for_quote_http_error is _raise_for_http_error


def test_quote_alias_signature_matches_new_dispatcher():
    """Defense in depth: even if someone bypassed the identity check (e.g.
    by aliasing to a ``functools.wraps``-decorated wrapper that copies the
    signature), this test pins the exact keyword-only ``fallback_exc``
    contract. Callers relying on the old name MUST be able to call
    ``_raise_for_quote_http_error(err, fallback_exc=InvalidOptionId)``.
    """
    import inspect

    from pyrh.robinhood import _raise_for_http_error, _raise_for_quote_http_error

    old_sig = inspect.signature(_raise_for_quote_http_error)
    new_sig = inspect.signature(_raise_for_http_error)

    assert old_sig == new_sig, (
        "Alias signature drifted from the new dispatcher — callers using "
        "the old private name will break. Either revert the alias to "
        "assignment (``_raise_for_quote_http_error = _raise_for_http_error``) "
        "or update this BC pin intentionally."
    )

    # Explicit pin on the keyword-only arg callers depend on.
    assert "fallback_exc" in old_sig.parameters
    assert old_sig.parameters["fallback_exc"].kind == inspect.Parameter.KEYWORD_ONLY
