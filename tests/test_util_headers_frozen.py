# coding=utf-8
"""Issue #187 — ``pyrh.util.headers`` and ``pyrh.util.robinhood_headers``
must be frozen (``MappingProxyType`` read-only views) so downstream callers
cannot silently mutate what looks like a module-level constant.

Blast-radius note (from issue #187):
- ``robinhood_headers`` is read exactly once at import time in
  ``pyrh/models/sessionmanager.py`` via ``MappingProxyType(dict(robinhood_headers))``,
  so today's mutation leak risk is lower than the ``HEADERS`` case (issue #76)
  that motivated this sweep. Defense-in-depth still matters — a future
  refactor that re-reads ``robinhood_headers`` on each call would silently
  re-open the leak.
- ``headers`` has no internal readers at all; it is exported publicly but
  never imported within pyrh. Any downstream caller who *thinks* mutating
  it changes pyrh behavior is silently wrong — freezing turns that silent
  wrongness into an explicit TypeError.

Guarantees this test locks in:
1. Both names still import from ``pyrh.util`` (public API unchanged).
2. Both still behave as read-only mappings — ``["key"]`` / ``in`` / ``len``
   / ``dict(x)`` / iteration all work.
3. Mutation (``x["X"] = ...``) raises ``TypeError``.
4. ``pyrh.models.sessionmanager.HEADERS`` — the consumer-side frozen view
   — still contains the expected Robinhood-specific header keys after the
   module-level freeze change (no accidental regressions to #76's fix).
"""
import pytest


# ---------------------------------------------------------------------------
# Importability — issue #187 cannot be closed by simply deleting the names.
# ---------------------------------------------------------------------------


def test_headers_is_importable_from_pyrh_util():
    from pyrh.util import headers  # noqa: F401


def test_robinhood_headers_is_importable_from_pyrh_util():
    from pyrh.util import robinhood_headers  # noqa: F401


# ---------------------------------------------------------------------------
# Read-path invariants — freezing MUST NOT change any read-side behavior.
# ---------------------------------------------------------------------------


def test_headers_read_path_unchanged():
    from pyrh.util import headers

    # The User-Agent string is the only key in ``headers``; assertions on
    # its exact value live in the upstream commit history. Here we assert
    # it's still a mapping with the expected key + a non-empty value.
    assert "User-Agent" in headers
    assert isinstance(headers["User-Agent"], str)
    assert len(headers["User-Agent"]) > 0
    # dict(...) must still accept the mapping — sessionmanager uses this.
    assert dict(headers) == {"User-Agent": headers["User-Agent"]}


def test_robinhood_headers_read_path_unchanged():
    from pyrh.util import robinhood_headers

    # Lock in the set of keys that the HEADERS mapping downstream depends
    # on. Values are allowed to float (User-Agent string refreshes, API
    # version bumps, etc.) — names are the stable contract.
    expected_keys = {
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "X-Robinhood-Api-Version",
        "Connection",
        "Content-Type",
        "Origin",
        "Referer",
        "Priority",
        "User-Agent",
    }
    assert set(robinhood_headers.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Freeze invariants — mutation MUST raise TypeError.
# ---------------------------------------------------------------------------


def test_headers_rejects_mutation():
    from pyrh.util import headers

    with pytest.raises(TypeError):
        headers["X-Custom"] = "leaks-into-every-session"


def test_headers_rejects_deletion():
    from pyrh.util import headers

    with pytest.raises(TypeError):
        del headers["User-Agent"]


def test_robinhood_headers_rejects_mutation():
    from pyrh.util import robinhood_headers

    with pytest.raises(TypeError):
        robinhood_headers["X-Custom"] = "leaks-into-every-session"


def test_robinhood_headers_rejects_deletion():
    from pyrh.util import robinhood_headers

    with pytest.raises(TypeError):
        del robinhood_headers["User-Agent"]


# ---------------------------------------------------------------------------
# Consumer-side — ensure the sessionmanager-level HEADERS view still works.
# ---------------------------------------------------------------------------


def test_sessionmanager_HEADERS_still_populated():
    """``HEADERS`` is built from ``dict(robinhood_headers)`` at import time;
    freezing ``robinhood_headers`` must not break that.
    """
    from pyrh.models.sessionmanager import HEADERS

    assert "User-Agent" in HEADERS
    assert "X-Robinhood-Api-Version" in HEADERS
    # HEADERS was already frozen by issue #76 — keep that invariant.
    with pytest.raises(TypeError):
        HEADERS["X-Break-76"] = "no"
