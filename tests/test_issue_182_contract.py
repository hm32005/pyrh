# coding=utf-8
"""Independent QA contract tests for issue #182.

These tests verify the two behavior fixes landed for issue #182 without
looking at the coding-agent's own tests. Each assertion pins a concrete,
user-observable URL shape so mutation of either fix causes a failure
here.

Bug 1 — ``InstrumentManager.instruments(query="foo")`` silently dropped
the query because the ternary branches were inverted. The resulting URL
must actually contain the query keyword.

Bug 2 — ``Robinhood.get_popularity`` called
``urls.instruments(stock_instrument, "popularity")`` positionally, which
routed the instrument id to ``symbol=`` and the literal string
``"popularity"`` to ``query=``, producing ``/instruments/?symbol=<id>``.
The correct URL shape is ``/instruments/<id>/popularity/``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from yarl import URL

from pyrh import urls
from pyrh.models.instrument import InstrumentManager


# ---------------------------------------------------------------------------
# Bug 1: query keyword must survive to the final URL.
# ---------------------------------------------------------------------------


def test_urls_instruments_query_keyword_present_in_url() -> None:
    """Spec test 1 — ``urls.instruments(query="foo")`` must embed ``foo``.

    Before the #78 tightening this branch could silently fall through; the
    test asserts the literal keyword is present in the URL's query string
    so any regression (branch invert, dropped arg) trips here.
    """
    url = urls.instruments(query="foo")

    assert "foo" in str(url)
    # pin the actual query parameter name so a rename to e.g. ``q=`` would
    # surface as a failure rather than sneak through on substring match.
    assert url.query.get("query") == "foo"


def test_urls_INSTRUMENTS_BASE_is_no_query_path() -> None:
    """Spec test 2 — the no-query path uses the plain ``/instruments/`` base.

    ``InstrumentManager.instruments()`` (no query) routes around
    ``urls.instruments`` entirely and hits ``urls.INSTRUMENTS_BASE``
    directly because the tightened ``urls.instruments()`` (issue #78) now
    raises when given no arguments. Lock in the constant's shape so the
    no-query fallback stays valid.
    """
    assert urls.INSTRUMENTS_BASE == URL("https://api.robinhood.com/instruments/")
    # query string must be empty — this is the "listing" endpoint.
    assert urls.INSTRUMENTS_BASE.query_string == ""


def test_instrument_manager_instruments_passes_query_to_url_builder() -> None:
    """Spec test 3 — model layer actually threads ``query`` through.

    We construct an ``InstrumentManager`` without going through the real
    ``__init__`` (it wants auth state) and stub ``.get`` so we can observe
    the seed URL that ``base_paginator`` hands to the session. Pulling a
    single item off the generator is enough to trigger one ``.get`` call.
    """
    manager = InstrumentManager.__new__(InstrumentManager)

    captured: dict = {}

    def fake_get(url, schema=None):  # noqa: ANN001
        captured["url"] = url
        # return an object with ``.next = None`` and an empty iterator so
        # the paginator terminates cleanly after one page.
        page = MagicMock()
        page.next = None
        page.__iter__ = lambda self: iter([])
        return page

    manager.get = fake_get  # type: ignore[attr-defined]

    # consume the generator to force the first get() call.
    list(manager.instruments(query="apple"))

    assert "url" in captured, "session_manager.get was never called"
    assert "apple" in str(captured["url"])
    assert captured["url"].query.get("query") == "apple"


# ---------------------------------------------------------------------------
# Bug 2: get_popularity URL must end with /popularity/.
# ---------------------------------------------------------------------------


def test_get_popularity_builds_instrument_popularity_url_shape() -> None:
    """Spec test 4 — popularity URL must be ``.../instruments/<id>/popularity/``.

    We drive the real ``Robinhood.get_popularity`` method with stubbed
    dependencies so the URL the method actually hands to ``get_url`` is
    observed end-to-end. The buggy positional call site produced
    ``/instruments/?symbol=<id>`` — we assert the fixed path shape and
    pin the absence of the buggy query string.
    """
    from pyrh.robinhood import Robinhood

    stock_instrument = "fake-instrument-id-123"
    rh = Robinhood.__new__(Robinhood)

    rh.quote_data = lambda stock: {"instrument": "https://example/ignored/"}  # type: ignore[attr-defined]

    captured_urls: list = []

    def fake_get_url(url, schema=None):  # noqa: ANN001
        captured_urls.append(url)
        # the first get_url call asks for the instrument record (to pull
        # the id); the second asks for popularity. Return shapes matching
        # what get_popularity expects so it doesn't raise.
        if len(captured_urls) == 1:
            return {"id": stock_instrument}
        return {"num_open_positions": 42}

    rh.get_url = fake_get_url  # type: ignore[attr-defined]

    result = rh.get_popularity("FAKE")

    assert result == 42
    # second captured url is the popularity URL.
    assert len(captured_urls) == 2, captured_urls
    popularity_url = captured_urls[1]
    url_str = str(popularity_url)
    assert url_str.endswith(f"/instruments/{stock_instrument}/popularity/"), url_str
    # the buggy shape was /instruments/?symbol=<id>; make sure we are NOT
    # producing that.
    assert "symbol=" not in url_str
    assert "?" not in url_str  # no query string on the popularity endpoint


def test_get_popularity_source_uses_id_keyword_not_positional() -> None:
    """Spec test 5 — mutation guard on the get_popularity call site.

    Reverting the fix means changing the call back to
    ``urls.instruments(stock_instrument, "popularity")`` (positional) or
    otherwise dropping the ``id_=`` keyword and the ``/ "popularity/"``
    append. Parse the source to make either regression visible.
    """
    import inspect

    from pyrh import robinhood

    source = inspect.getsource(robinhood.Robinhood.get_popularity)

    # the fix threads the id through ``id_=`` and appends ``/ "popularity/"``.
    assert "id_=stock_instrument" in source, (
        "get_popularity no longer passes stock_instrument via id_= kwarg"
    )
    assert '/ "popularity/"' in source, (
        "get_popularity no longer appends /popularity/ to the instrument URL"
    )
    # the buggy positional form must not reappear.
    assert 'urls.instruments(stock_instrument, "popularity")' not in source
