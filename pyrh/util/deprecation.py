# coding=utf-8
"""Helpers for backward-compatible kwarg renames.

When a public API renames a keyword argument, callers on the old name get
``TypeError: unexpected keyword argument`` unless the method accepts both
names and forwards the value. This module centralises that shim so every
renamed-kwarg method handles the transition identically.

Why one helper instead of per-method code:
    - Consistent DeprecationWarning message (so downstream linters /
      filters can match a single pattern).
    - Consistent behavior when both names are passed (always TypeError,
      never silent precedence).
    - One place to bump ``stacklevel`` if the call chain changes.
"""
import warnings
from typing import Any


def coalesce_deprecated_kwarg(
    new_name: str,
    new_value: Any,
    old_name: str,
    old_value: Any,
    *,
    stacklevel: int = 3,
) -> Any:
    """Resolve a renamed keyword argument.

    If the caller passed the old name, emit a ``DeprecationWarning`` and
    return that value. If the caller passed both names, raise ``TypeError``
    to prevent silent ambiguity. Otherwise return the new-name value.

    Args:
        new_name: Canonical (new) kwarg name — what the caller SHOULD pass.
        new_value: Value the caller passed under ``new_name`` (or ``None``).
        old_name: Deprecated kwarg name — accepted for backward compatibility.
        old_value: Value the caller passed under ``old_name`` (or ``None``).
        stacklevel: Passed to ``warnings.warn``. Default ``3`` surfaces the
            warning at the caller of the method that invoked this helper
            (helper → method → caller = 3).

    Returns:
        The resolved value (either ``new_value`` or ``old_value``).

    Raises:
        TypeError: if both ``new_value`` and ``old_value`` are non-``None``.

    """
    if old_value is not None:
        if new_value is not None:
            raise TypeError(
                f"Pass {new_name!r}; {old_name!r} is deprecated and "
                f"conflicts with {new_name!r}"
            )
        warnings.warn(
            f"{old_name!r} is deprecated; use {new_name!r} instead",
            DeprecationWarning,
            stacklevel=stacklevel,
        )
        return old_value
    return new_value
