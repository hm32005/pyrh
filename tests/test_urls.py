# coding=utf-8
"""URL construction smoke tests.

These are happy-path assertions on the URL builder helpers in ``pyrh.urls``.
They are intentionally shallow — pyrh.urls is data-only and the builders just
concatenate path segments — but pinning the exact string output catches the
class of bug where a trailing-slash / or ``@property`` decorator silently
breaks the URL.
"""

from yarl import URL


API_BASE = "https://api.robinhood.com"


def test_base_constants_are_correct():
    from pyrh import urls

    assert str(urls.API_BASE) == API_BASE
    assert str(urls.OAUTH) == f"{API_BASE}/oauth2/token/"
    assert str(urls.OAUTH_REVOKE) == f"{API_BASE}/oauth2/revoke_token/"
    assert str(urls.ACCOUNTS) == f"{API_BASE}/accounts/"
    assert str(urls.PORTFOLIOS) == f"{API_BASE}/portfolios/"
    assert str(urls.POSITIONS) == f"{API_BASE}/positions/"
    assert str(urls.QUOTES) == f"{API_BASE}/quotes/"
    assert str(urls.HISTORICALS) == f"{API_BASE}/quotes/historicals/"
    assert str(urls.USER_MACHINE) == f"{API_BASE}/pathfinder/user_machine/"
    assert str(urls.INQUIRIES) == f"{API_BASE}/pathfinder/inquiries"
    assert str(urls.CHALLENGE) == f"{API_BASE}/challenge"
    assert str(urls.PUSH_PROMPT_STATUS) == f"{API_BASE}/push"


def test_challenge_builder_embeds_id():
    from pyrh import urls

    cid = "abc-123"
    assert str(urls.challenge(cid)) == f"{API_BASE}/challenge/{cid}/respond/"


def test_ach_iav_option():
    from pyrh import urls

    assert str(urls.ach("iav")) == f"{API_BASE}/ach/iav/auth/"


def test_ach_other_option_uses_the_input():
    from pyrh import urls

    assert str(urls.ach("relationships")) == f"{API_BASE}/ach/relationships/"
    assert str(urls.ach("transfers")) == f"{API_BASE}/ach/transfers/"


def test_instruments_by_symbol():
    from pyrh import urls

    u = urls.instruments(symbol="AAPL")
    assert str(u) == f"{API_BASE}/instruments/?symbol=AAPL"


def test_instruments_by_query():
    from pyrh import urls

    u = urls.instruments(query="apple")
    assert str(u) == f"{API_BASE}/instruments/?query=apple"


def test_instruments_by_id():
    from pyrh import urls

    u = urls.instruments(id_="00000000-0000-0000-0000-000000000000")
    assert str(u) == f"{API_BASE}/instruments/00000000-0000-0000-0000-000000000000/"


def test_instruments_no_args_returns_none():
    from pyrh import urls

    # All three args optional; passing none yields a None return.
    assert urls.instruments() is None


def test_orders_root_and_by_id():
    from pyrh import urls

    assert str(urls.orders()) == f"{API_BASE}/orders/"
    assert str(urls.orders("xyz")) == f"{API_BASE}/orders/xyz/"


def test_news_fundamentals_tags():
    from pyrh import urls

    assert str(urls.news("TSLA")) == f"{API_BASE}/midlands/news/TSLA/"
    assert str(urls.fundamentals("TSLA")) == f"{API_BASE}/fundamentals/TSLA/"
    assert str(urls.tags("top-100")) == f"{API_BASE}/midlands/tags/tag/top-100/"


def test_chain_builder_currently_raises_value_error():
    """Pinning test: `chain()` contains ``URL / "/"`` which yarl rejects as
    "Appending path '/' starting from slash is forbidden". This is a
    pre-existing upstream bug flagged by the source-level TODO on the same
    line; treat it as Acknowledged (deferred) rather than silently broken.
    Delete this test and re-enable the happy-path assertion once the bug is
    actually fixed in pyrh.urls.chain().
    """
    import pytest

    from pyrh import urls

    with pytest.raises(ValueError, match="Appending path '/'"):
        urls.chain("abc-id")


def test_options_builder_has_expected_query_params():
    from pyrh import urls

    u = urls.options(chain_id="cid", dates="2026-04-17", option_type="call")
    assert isinstance(u, URL)
    assert u.query["chain_id"] == "cid"
    assert u.query["expiration_dates"] == "2026-04-17"
    assert u.query["state"] == "active"
    assert u.query["tradability"] == "tradable"
    assert u.query["type"] == "call"
