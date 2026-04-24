# coding=utf-8
"""Unit tests for ``Robinhood.get_news`` pagination + limit handling.

Motivation (cross-repo): investment-system's ``rh_news_daily_collector.py``
currently bypasses pyrh and calls ``GET /midlands/news/{ticker}/`` directly
via ``requests`` because the existing ``Robinhood.get_news`` wrapper (a) only
returned the raw single-page response dict, (b) did not follow the ``next``
pagination cursor, and (c) had no ``limit`` knob. That leaked the Robinhood
API boundary into IS. This test module pins the new contract:

    1. ``get_news(ticker)`` returns a **list of article dicts** (merged
       across pages), not the raw response wrapper.
    2. ``get_news(ticker)`` follows the ``next`` cursor until exhausted.
    3. ``get_news(ticker, limit=N)`` stops once N articles have been
       collected (may stop mid-page).
    4. Empty response returns ``[]`` (not ``None``, not a dict).
    5. Pathological pagination (cycle / infinite ``next``) is capped.

Test style mirrors ``tests/test_robinhood_options_pagination_and_batch.py``:
bypass ``__init__`` via ``Robinhood.__new__(Robinhood)`` and patch
``pyrh.robinhood.Robinhood.get_url`` with a deterministic response
sequence.

Observed response-dict fields (from direct-HTTP scraping in
``investment-system/core/research/rh_news_archive.py``): ``uuid``, ``url``,
``source``, ``title``, ``summary``, ``author``, ``published_at``,
``updated_at``, ``preview_image_url``, ``preview_text``, ``relay_url``,
``num_clicks``, ``currency_id``, ``api_source``, ``related_instruments``.
Tests use a minimal subset — the method must preserve unknown fields
verbatim so downstream analyzers can discover new ones.
"""
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fresh_robinhood():
    """Return a ``Robinhood`` instance bypassing ``__init__`` (no auth)."""
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


def _article(uuid, title="t", published_at="2026-04-20T12:00:00Z"):
    """Minimal news-article dict for fixture building."""
    return {
        "uuid": uuid,
        "title": title,
        "published_at": published_at,
        "url": f"https://example.com/{uuid}",
        "source": "test-source",
    }


# ---------------------------------------------------------------------------
# 1. Single-page response
# ---------------------------------------------------------------------------


def test_get_news_returns_flat_list_of_articles_for_single_page():
    """``get_news`` must return the ``results`` list, not the wrapper dict.

    Legacy behaviour (pre-refactor) returned the raw response dict
    ``{count, next, previous, results}``. Callers had to dig into
    ``["results"]``. The new contract returns the list directly.
    """
    rh = _fresh_robinhood()

    page1 = {
        "next": None,
        "previous": None,
        "results": [_article("u1"), _article("u2"), _article("u3")],
    }

    def fake_get_url(self, url, schema=None):
        return page1

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL")

    assert isinstance(result, list)
    assert [a["uuid"] for a in result] == ["u1", "u2", "u3"]


# ---------------------------------------------------------------------------
# 2. Pagination
# ---------------------------------------------------------------------------


def test_get_news_follows_pagination_until_exhausted():
    """Multi-page response must be merged into one flat list in page order.

    RH documents ``next: null`` on the midlands/news endpoint today, but the
    paginator contract exists (the response shape has a ``next`` field) and
    a pyrh wrapper must follow it if the server ever starts emitting one —
    otherwise silent data loss the moment pagination turns on.
    """
    rh = _fresh_robinhood()

    page1 = {
        "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=p2",
        "results": [_article("u1"), _article("u2")],
    }
    page2 = {
        "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=p3",
        "results": [_article("u3")],
    }
    page3 = {
        "next": None,
        "results": [_article("u4")],
    }
    responses = [page1, page2, page3]
    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        i = counter["n"]
        counter["n"] += 1
        return responses[i]

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL")

    assert [a["uuid"] for a in result] == ["u1", "u2", "u3", "u4"]
    assert counter["n"] == 3  # three page fetches


# ---------------------------------------------------------------------------
# 3. limit knob
# ---------------------------------------------------------------------------


def test_get_news_respects_limit_and_stops_mid_page():
    """``limit=N`` must return exactly N articles even if it falls mid-page.

    Scenario: 3 pages of 50 articles each. ``limit=75`` must return the
    first 50 from page 1 + the first 25 from page 2 (exactly 75 articles
    in input order) and must NOT fetch page 3.
    """
    rh = _fresh_robinhood()

    page1 = {
        "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=p2",
        "results": [_article(f"p1-{i}") for i in range(50)],
    }
    page2 = {
        "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=p3",
        "results": [_article(f"p2-{i}") for i in range(50)],
    }
    page3 = {
        "next": None,
        "results": [_article(f"p3-{i}") for i in range(50)],
    }
    responses = [page1, page2, page3]
    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        i = counter["n"]
        counter["n"] += 1
        return responses[i]

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL", limit=75)

    assert len(result) == 75
    # First 50 from page 1, then the first 25 from page 2.
    expected = [f"p1-{i}" for i in range(50)] + [f"p2-{i}" for i in range(25)]
    assert [a["uuid"] for a in result] == expected
    # Only 2 fetches — page 3 must not be requested after limit reached.
    assert counter["n"] == 2


def test_get_news_limit_none_returns_all_pages():
    """``limit=None`` (default) must return every article across all pages."""
    rh = _fresh_robinhood()

    page1 = {
        "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=p2",
        "results": [_article("u1"), _article("u2")],
    }
    page2 = {
        "next": None,
        "results": [_article("u3"), _article("u4"), _article("u5")],
    }
    responses = [page1, page2]
    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        i = counter["n"]
        counter["n"] += 1
        return responses[i]

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL", limit=None)

    assert [a["uuid"] for a in result] == ["u1", "u2", "u3", "u4", "u5"]


# ---------------------------------------------------------------------------
# 4. Empty response
# ---------------------------------------------------------------------------


def test_get_news_handles_empty_results():
    """Empty response (e.g. unknown ticker, no news) must return ``[]``."""
    rh = _fresh_robinhood()

    def fake_get_url(self, url, schema=None):
        return {"next": None, "previous": None, "results": []}

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("NOSUCH")

    assert result == []


# ---------------------------------------------------------------------------
# 5. Safety cap against pathological pagination
# ---------------------------------------------------------------------------


def test_get_news_safety_cap_prevents_infinite_loop():
    """A server that keeps returning a ``next`` URL forever must not spin.

    Contract: the method stops at a safety cap WITHOUT raising, returning
    whatever was collected. Mirrors ``get_options`` cap semantics so a
    broken paginator response never hangs the caller. Cap chosen must be
    finite and < 1000 iterations.
    """
    rh = _fresh_robinhood()

    counter = {"n": 0}

    def fake_get_url(self, url, schema=None):
        counter["n"] += 1
        return {
            "next": "https://api.robinhood.com/midlands/news/AAPL/?cursor=forever",
            "results": [_article(f"u-{counter['n']}")],
        }

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL")

    # Must have stopped at the cap.
    assert counter["n"] < 1000, (
        f"get_news spun {counter['n']} times without a cap"
    )
    # Must return whatever was collected (a list of dicts), not raise.
    assert isinstance(result, list)
    assert len(result) == counter["n"]


# ---------------------------------------------------------------------------
# 6. Preserve response-dict fields verbatim
# ---------------------------------------------------------------------------


def test_get_news_preserves_all_article_fields():
    """Unknown fields in the response dict must be preserved verbatim.

    Downstream (IS archive) snapshots the full dict so future analyzers
    can discover fields this library doesn't explicitly parse. Regression
    guard: if a future refactor strips fields, this test fails.
    """
    rh = _fresh_robinhood()

    full_article = {
        "uuid": "abc",
        "url": "https://example.com/x",
        "source": "Reuters",
        "title": "Something happened",
        "summary": "Details here",
        "author": "Jane Doe",
        "published_at": "2026-04-20T12:00:00Z",
        "updated_at": "2026-04-20T12:05:00Z",
        "preview_image_url": "https://example.com/img.png",
        "preview_text": "Preview...",
        "relay_url": "https://robinhood.com/relay/x",
        "num_clicks": 42,
        "currency_id": None,
        "api_source": "rh-newsapi",
        "related_instruments": ["https://api.robinhood.com/instruments/xyz/"],
        "brand_new_field_robinhood_added_later": "surprise",
    }

    def fake_get_url(self, url, schema=None):
        return {"next": None, "results": [full_article]}

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.get_news("AAPL")

    assert len(result) == 1
    # Dict must be preserved verbatim — no field-filtering.
    assert result[0] == full_article
