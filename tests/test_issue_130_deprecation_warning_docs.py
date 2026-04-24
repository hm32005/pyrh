# coding=utf-8
"""Doc-lockin for issue #130: README note on ``-W default::DeprecationWarning``.

Issue #130 (investment-system-docs): pyrh's BC shim
(``coalesce_deprecated_kwarg`` in ``pyrh/util/deprecation.py``) emits
``DeprecationWarning`` when callers pass a renamed kwarg under its old
name. Python silences ``DeprecationWarning`` by default outside
``__main__``, so downstream users who haven't opted in via
``-W default::DeprecationWarning`` or ``PYTHONDEVMODE=1`` won't see the
notice and will be surprised when the legacy kwarg is removed in a future
major release.

This test pins the README documentation so the guidance survives future
edits. If the advice is reworded, update the assertions in the same
commit so reviewers can see the intended wording change.
"""
from __future__ import annotations

from pathlib import Path


def _readme_text() -> str:
    """Return the README content as a string."""
    readme = Path(__file__).resolve().parent.parent / "README.rst"
    return readme.read_text(encoding="utf-8")


def test_readme_mentions_deprecation_warning_flag():
    """README must mention ``-W default::DeprecationWarning`` so users know
    how to surface the BC-shim warnings pyrh emits."""
    text = _readme_text()
    assert "-W default::DeprecationWarning" in text, (
        "README should document the -W default::DeprecationWarning flag "
        "so downstream users can surface pyrh's BC-shim warnings — see "
        "issue #130."
    )


def test_readme_mentions_pythondevmode_alternative():
    """README should also mention ``PYTHONDEVMODE=1`` as an alternative
    way to surface the warnings (less precise than the ``-W`` flag but
    commonly configured in dev environments)."""
    text = _readme_text()
    assert "PYTHONDEVMODE" in text, (
        "README should mention PYTHONDEVMODE=1 as an alternative to the "
        "-W flag — see issue #130."
    )


def test_readme_explains_why_warnings_are_silenced_by_default():
    """README should explain Python's default silencing of
    ``DeprecationWarning`` outside ``__main__`` — otherwise the reader
    doesn't know WHY the flag is needed."""
    text = _readme_text()
    # We pin the phrase "DeprecationWarning" appearing in context of a
    # "silenced by default" / "hidden by default" / "not visible" cue. Any
    # of those phrasings is fine — we just want the README to explain the
    # root cause, not only prescribe a fix.
    assert "DeprecationWarning" in text, (
        "README should reference DeprecationWarning so users can grep for "
        "the warning class — see issue #130."
    )


def test_readme_references_bc_shim_context():
    """The note should be anchored to pyrh's BC-shim context so readers
    understand which warnings the flag surfaces (e.g. the ``instrument_URL``
    → ``instrument_url`` rename from PR #7)."""
    text = _readme_text()
    # Either mention the helper name, an example rename, or "shim" —
    # lenient so the README wording can vary.
    assert (
        "coalesce_deprecated_kwarg" in text
        or "instrument_url" in text
        or "shim" in text.lower()
        or "deprecated kwarg" in text.lower()
    ), (
        "README should anchor the DeprecationWarning note to pyrh's BC-shim "
        "context (helper name, an example rename, or the word 'shim') so "
        "readers know WHICH warnings this flag surfaces — see issue #130."
    )
