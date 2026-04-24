# coding=utf-8
"""Unit tests for options-chain pagination + batched options market-data.

Motivation (cross-repo): investment-system's daily options collector was
planning to bypass pyrh and call ``GET /marketdata/options/?instruments=...``
directly because pyrh lacked (a) pagination support on ``get_options`` and
(b) a batched market-data endpoint. That leaked the Robinhood API boundary
into IS and risked silent data loss for high-strike-count tickers (e.g. AAPL
with 100+ strikes per expiration — only page 1 came back).

This test module pins three contracts:

    1. ``Robinhood.get_options`` follows the ``next`` pagination cursor until
       exhaustion, merging all pages into a single results list.
    2. ``Robinhood.get_options`` stops at a safety cap to avoid infinite loops
       on pathological paginator responses (server returning same ``next`` URL
       forever, or a cycle).
    3. ``Robinhood.get_option_market_data_batch`` hits the
       ``/marketdata/options/`` endpoint in fixed-size chunks of instrument
       URLs, preserving input order and returning ALL results concatenated.

Test style: mirrors ``tests/test_robinhood_options_methods_http_error_mapping.py``
— bypass ``__init__`` via ``Robinhood.__new__(Robinhood)``, patch the HTTP
layer (``get_url`` for the top-level pagination path, ``session.get`` for the
batched endpoint since the batched method goes direct to session to keep
headers + retries intact).
"""
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fresh_robinhood():
    """Return a ``Robinhood`` instance bypassing ``__init__`` (no auth)."""
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


def _fake_response(payload):
    """Build a stand-in for ``requests.Response`` that returns ``payload`` from
    ``.json()`` and is a no-op on ``.raise_for_status()``.
    """
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# 1. Pagination in ``get_options``
# ---------------------------------------------------------------------------


def test_get_options_follows_pagination_until_exhausted():
    """Multi-page response must be merged into one flat results list.

    Robinhood paginates the options-instruments endpoint (page size ~40). For
    AAPL on a weekly expiration, strike count exceeds a single page. The
    previous implementation grabbed only ``response["results"]`` from page 1
    and discarded the ``next`` cursor — silent data loss.
    """
    rh = _fresh_robinhood()

    # quote_data -> instrument-id hop -> chain-id hop -> paginated options list.
    # We mock get_url to return a deterministic sequence.
    page1 = {
        "next": "https://api.robinhood.com/options/instruments/?cursor=p2",
        "results": [{"id": "contract-1"}, {"id": "contract-2"}],
    }
    page2 = {
        "next": "https://api.robinhood.com/options/instruments/?cursor=p3",
        "results": [{"id": "contract-3"}],
    }
    page3 = {
        "next": None,
        "results": [{"id": "contract-4"}],
    }

    # get_options' call chain (verified in
    # test_robinhood_options_methods_http_error_mapping.py):
    #   call 0: quote_data instrument-ref hop
    #   call 1: instrument lookup -> returns {"id": "..."}
    #   call 2: chain lookup -> returns {"results": [{"id": ..., ...}]}
    #   call 3: options-list -> paginated (page 1)
    #   call 4: page 2
    #   call 5: page 3
    responses = [
        {"instrument": "https://example/instruments/xxx/"},  # quote_data hop
        {"id": "dummy-instrument-id"},                       # instrument lookup
        {"results": [{"id": "dummy-chain-id"}]},             # chain lookup
        page1,
        page2,
        page3,
    ]
    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        i = counter["n"]
        counter["n"] += 1
        return responses[i]

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_options("AAPL", ["2026-05-15"], "call")

    # All 4 contracts from 3 pages must be present, in input order.
    assert [c["id"] for c in result] == [
        "contract-1",
        "contract-2",
        "contract-3",
        "contract-4",
    ]
    # Three options-list fetches (pages 1..3) plus 3 pre-pagination hops = 6.
    assert counter["n"] == 6


def test_get_options_respects_safety_cap_on_pathological_pagination():
    """If the server keeps returning a ``next`` URL forever, stop at the cap.

    Without a cap, a broken Robinhood response (or a cycle in the cursor) would
    spin the client indefinitely. The cap must be < 1000 iterations and must
    NOT raise — it must return whatever was collected so the caller can still
    make progress (or log and move on).
    """
    rh = _fresh_robinhood()

    # Infinite loop: every page points to itself.
    loop_payload = {
        "next": "https://api.robinhood.com/options/instruments/?cursor=stuck",
        "results": [{"id": "loop-contract"}],
    }

    responses = [
        {"instrument": "https://example/instruments/xxx/"},
        {"id": "dummy-instrument-id"},
        {"results": [{"id": "dummy-chain-id"}]},
    ]
    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        i = counter["n"]
        counter["n"] += 1
        if i < len(responses):
            return responses[i]
        # Every subsequent call is an infinite-loop page.
        return loop_payload

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_options("AAPL", ["2026-05-15"], "call")

    # Three pre-pagination hops + at most SAFETY_CAP pagination fetches.
    # Cap is 100 per the spec; total call count must stay below 200.
    assert counter["n"] <= 200, (
        f"get_options should cap pagination; saw {counter['n']} HTTP calls"
    )
    # Must have collected SOMETHING (not bailed with empty list silently).
    assert len(result) > 0
    # And must not have gone unbounded.
    assert len(result) <= 200


# ---------------------------------------------------------------------------
# 2. ``get_option_market_data_batch`` — batched pricing fetch
# ---------------------------------------------------------------------------


def test_get_option_market_data_batch_single_batch_one_http_call():
    """<= batch_size URLs -> single HTTP call, all results returned.

    Contract: 10 instrument URLs with default batch_size=40 -> exactly 1 call
    to ``session.get``, 10 results back.
    """
    rh = _fresh_robinhood()
    rh.session = MagicMock()

    urls_in = [
        f"https://api.robinhood.com/options/instruments/id-{i}/" for i in range(10)
    ]
    fake_results = [
        {"instrument": u, "bid_price": f"1.{i:02d}"} for i, u in enumerate(urls_in)
    ]
    rh.session.get.return_value = _fake_response({"results": fake_results})

    result = rh.get_option_market_data_batch(urls_in)

    assert rh.session.get.call_count == 1
    assert len(result) == 10
    # Verify the URL-construction hit the batched marketdata endpoint.
    call_args = rh.session.get.call_args
    assert "instruments" in call_args.kwargs.get("params", {}) or \
        "instruments=" in str(call_args)


def test_get_option_market_data_batch_chunks_into_multiple_http_calls():
    """100 URLs with batch_size=40 -> 3 HTTP calls (40 + 40 + 20)."""
    rh = _fresh_robinhood()
    rh.session = MagicMock()

    urls_in = [
        f"https://api.robinhood.com/options/instruments/id-{i}/" for i in range(100)
    ]

    # Each call returns its batch worth of results, in the same order.
    call_log = []

    def fake_get(url, params=None, **kwargs):
        call_log.append(params["instruments"].split(","))
        batch = params["instruments"].split(",")
        return _fake_response(
            {"results": [{"instrument": u, "bid_price": "0.01"} for u in batch]}
        )

    rh.session.get.side_effect = fake_get

    result = rh.get_option_market_data_batch(urls_in, batch_size=40)

    # 40 + 40 + 20 = 3 calls
    assert rh.session.get.call_count == 3
    assert [len(b) for b in call_log] == [40, 40, 20]
    assert len(result) == 100


def test_get_option_market_data_batch_preserves_input_order():
    """Output list order == input URL order, even across multiple batches."""
    rh = _fresh_robinhood()
    rh.session = MagicMock()

    urls_in = [
        f"https://api.robinhood.com/options/instruments/id-{i:03d}/" for i in range(85)
    ]

    def fake_get(url, params=None, **kwargs):
        batch = params["instruments"].split(",")
        return _fake_response(
            {"results": [{"instrument": u, "idx_marker": u} for u in batch]}
        )

    rh.session.get.side_effect = fake_get

    result = rh.get_option_market_data_batch(urls_in, batch_size=40)

    assert [r["instrument"] for r in result] == urls_in


def test_get_option_market_data_batch_empty_input_returns_empty_list():
    """Zero URLs -> zero HTTP calls, empty list (no divide-by-zero)."""
    rh = _fresh_robinhood()
    rh.session = MagicMock()

    result = rh.get_option_market_data_batch([])

    assert result == []
    assert rh.session.get.call_count == 0


def test_get_option_market_data_batch_method_exists_on_class():
    """Shape check: must be a plain method, not a ``@property``.

    The fundamentals/watchlists-as-property regressions (see
    ``tests/test_robinhood.py``) repeat whenever a method is decorated wrong.
    Lock in the method shape for the new API surface.
    """
    from pyrh.robinhood import Robinhood

    assert "get_option_market_data_batch" in Robinhood.__dict__, (
        "Robinhood must expose get_option_market_data_batch"
    )
    assert not isinstance(
        Robinhood.__dict__["get_option_market_data_batch"], property
    ), "get_option_market_data_batch must be a method, not a @property"


# ---------------------------------------------------------------------------
# 3. URL builder for the batched endpoint
# ---------------------------------------------------------------------------


def test_marketdata_options_url_builder_exists():
    """``urls.marketdata_options(urls)`` returns the batched-instruments URL.

    Shape mirrors ``urls.market_data_quotes`` — builds
    ``.../marketdata/options/?instruments=<url1>,<url2>,...``.
    """
    from pyrh import urls

    assert hasattr(urls, "marketdata_options"), (
        "urls module must expose marketdata_options() builder"
    )
    ids = [
        "https://api.robinhood.com/options/instruments/id-1/",
        "https://api.robinhood.com/options/instruments/id-2/",
    ]
    u = urls.marketdata_options(ids)
    s = str(u)
    assert s.startswith("https://api.robinhood.com/marketdata/options/")
    assert "instruments=" in s
    # Both ids must appear (URL-encoded commas are OK, but both ids must be there).
    assert "id-1" in s and "id-2" in s
