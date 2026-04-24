# coding=utf-8
"""Regression tests for issue #182.

Two latent bugs surfaced by PR #20 (#78) tightening:

1. ``pyrh/models/instrument.py`` — ``InstrumentManager.instruments(query)``
   had its branches flipped. When a query was supplied the code discarded
   it and used ``INSTRUMENTS_BASE``; when no query was supplied the code
   called ``urls.instruments(query=None)`` which — after #78 — raises
   ``ValueError`` rather than silently returning ``None``.

   Intended behavior:
       * ``instruments()``       -> hits ``INSTRUMENTS_BASE`` (no query)
       * ``instruments("apple")`` -> hits ``.../instruments/?query=apple``

2. ``pyrh/robinhood.py:get_popularity`` — called
   ``urls.instruments(stock_instrument, "popularity")`` with positional
   args, so ``stock_instrument`` landed in ``symbol=`` and the literal
   string ``"popularity"`` landed in ``query=``. The resulting URL is
   ``.../instruments/?symbol=<id>`` which is wrong for popularity lookup.

   Intended behavior: the popularity URL is
   ``.../instruments/<instrument_id>/popularity/`` — a different shape
   entirely. We fix the call site to build that URL directly rather than
   (ab)using ``urls.instruments``.

These tests are RED-first. Each asserts the *intended* URL or behavior
and will fail against the unfixed code.
"""

from unittest.mock import patch

from pyrh.models.instrument import (
    InstrumentManager,
    InstrumentPaginatorSchema,
)


API_BASE = "https://api.robinhood.com"


# ---------------------------------------------------------------------------
# Bug 1: InstrumentManager.instruments() — inverted branch.
#
# We capture the URL that ``base_paginator`` actually fetches by stubbing
# ``session_manager.get`` on the InstrumentManager. Avoids any real HTTP.
# ---------------------------------------------------------------------------


def _make_manager_capturing_get_url():
    """Return ``(manager, captured)`` — calling ``manager.instruments(...)``
    and consuming one item captures the URL passed to ``.get()``.
    """

    captured = {}

    class _Paginator:
        """Minimal stand-in for ``InstrumentPaginator`` — one empty page."""

        def __iter__(self):
            return iter([])

        next = None  # stop the paginator after one page

    class _FakeManager(InstrumentManager):
        def __init__(self):
            # Skip SessionManager.__init__ (needs real auth) — the tests
            # only exercise URL construction.
            pass

        def get(self, url, schema=None):  # noqa: D401 - mock
            captured["url"] = url
            captured["schema"] = schema
            return _Paginator()

    return _FakeManager(), captured


def test_instruments_no_query_uses_INSTRUMENTS_BASE():
    """``instruments()`` with no args must fetch ``/instruments/`` (no query)."""
    manager, captured = _make_manager_capturing_get_url()

    # ``instruments`` returns a generator; drain it to drive ``base_paginator``.
    list(manager.instruments())

    assert str(captured["url"]) == f"{API_BASE}/instruments/"


def test_instruments_with_query_embeds_query_in_url():
    """``instruments("apple")`` must fetch ``/instruments/?query=apple``.

    This is the core symptom: the inverted branch discards the user's
    ``query`` and hits ``INSTRUMENTS_BASE`` instead.
    """
    manager, captured = _make_manager_capturing_get_url()

    list(manager.instruments("apple"))

    assert str(captured["url"]) == f"{API_BASE}/instruments/?query=apple"


def test_instruments_with_query_kwarg_embeds_query_in_url():
    """Kwarg form — same expectation as the positional test above."""
    manager, captured = _make_manager_capturing_get_url()

    list(manager.instruments(query="tesla"))

    assert str(captured["url"]) == f"{API_BASE}/instruments/?query=tesla"


def test_instruments_paginator_schema_still_wired():
    """Sanity — regardless of branch, the schema passed is the paginator schema."""
    manager, captured = _make_manager_capturing_get_url()

    list(manager.instruments(query="apple"))

    assert isinstance(captured["schema"], InstrumentPaginatorSchema)


# ---------------------------------------------------------------------------
# Bug 2: Robinhood.get_popularity() — positional call to urls.instruments().
#
# The call ``urls.instruments(stock_instrument, "popularity")`` maps to
# ``symbol=<id>, query="popularity"`` so the first kwarg wins and returns
# ``.../instruments/?symbol=<id>``. Correct URL is
# ``.../instruments/<id>/popularity/``.
# ---------------------------------------------------------------------------


SENTINEL_INSTRUMENT_ID = "11223344-5566-7788-99aa-bbccddeeff00"


def _make_rh():
    """Bypass Robinhood.__init__ (needs live auth)."""
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


def test_get_popularity_hits_instrument_id_popularity_path():
    """``get_popularity`` must fetch ``/instruments/<id>/popularity/``.

    We patch ``quote_data`` (returns an instrument URL) and ``get_url``
    (records invocations and returns canned payloads). The first
    ``get_url`` fetches the instrument record (to extract the UUID); the
    second fetches the popularity endpoint — that's the one we assert.
    """
    rh = _make_rh()
    instrument_record_url = f"{API_BASE}/instruments/{SENTINEL_INSTRUMENT_ID}/"

    calls = []

    def fake_quote_data(self, stock=""):
        return {"instrument": instrument_record_url}

    def fake_get_url(self, url, schema=None):
        calls.append(str(url))
        # First call: fetch instrument record -> return {"id": <uuid>}
        if len(calls) == 1:
            return {"id": SENTINEL_INSTRUMENT_ID}
        # Second call: fetch popularity -> return {"num_open_positions": 42}
        return {"num_open_positions": 42}

    from pyrh.robinhood import Robinhood

    with patch.object(Robinhood, "quote_data", fake_quote_data), patch.object(
        Robinhood, "get_url", fake_get_url
    ):
        result = rh.get_popularity("AAPL")

    assert result == 42
    assert len(calls) == 2, f"expected 2 get_url calls, got {calls!r}"
    # Second call is the one under test.
    popularity_url = calls[1]
    expected = f"{API_BASE}/instruments/{SENTINEL_INSTRUMENT_ID}/popularity/"
    assert popularity_url == expected, (
        f"popularity URL wrong. expected {expected!r}, got {popularity_url!r}. "
        f"(The positional-args bug lands on "
        f"'{API_BASE}/instruments/?symbol={SENTINEL_INSTRUMENT_ID}'.)"
    )
