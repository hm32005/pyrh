# coding=utf-8
"""Context propagation sanity checks for GET-path call sites (issue #150).

Group A of #150 covers the quote / fundamentals / discovery-style GET-path
dispatcher sites: ``quote_data``, ``quotes_data``, ``get_stock_marketdata``,
``get_historical_quotes``, ``get_news``, ``get_popularity``,
``get_tickers_by_tag``, ``all_instruments``,
``get_symbol_from_instrument_url``, ``fundamentals``.

These tests confirm that the ``context=`` kwarg passed at each call site
propagates into the resulting exception message. We pick a representative
subset (quote_data / fundamentals / get_news / get_tickers_by_tag /
get_symbol_from_instrument_url) rather than re-asserting for every method
— the context plumbing is identical across sites, and Group A's dispatcher
contract is already pinned by
``test_dispatcher_context_kwarg.py::test_dispatcher_context_kwarg_invalid_ticker_symbol``.
"""
from unittest.mock import patch

import pytest
import requests


def _http_error(status_code):
    resp = requests.Response()
    resp.status_code = status_code
    return requests.exceptions.HTTPError(response=resp)


def _fresh_robinhood():
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


# ---------------------------------------------------------------------------
# quote_data — context: {"ticker": stock}
# ---------------------------------------------------------------------------


def test_quote_data_404_message_carries_ticker_context():
    from pyrh.exceptions import InvalidTickerSymbol

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidTickerSymbol) as exc_info:
            rh.quote_data("NOSUCH")

    assert "ticker=NOSUCH" in str(exc_info.value)


# ---------------------------------------------------------------------------
# fundamentals — context: {"ticker": stock.upper()}
# ---------------------------------------------------------------------------


def test_fundamentals_5xx_message_carries_ticker_context():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(503)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.fundamentals("tsla")

    msg = str(exc_info.value)
    assert "503" in msg
    assert "ticker=TSLA" in msg


# ---------------------------------------------------------------------------
# get_news — context: {"ticker": stock.upper()}
# ---------------------------------------------------------------------------


def test_get_news_429_message_carries_ticker_context():
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        err = _http_error(429)
        err.response.headers.update({"Retry-After": "3"})
        raise err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.get_news("aapl")

    assert "ticker=AAPL" in str(exc_info.value)
    assert exc_info.value.retry_after == 3


# ---------------------------------------------------------------------------
# get_tickers_by_tag — context: {"tag": tag}
# ---------------------------------------------------------------------------


def test_get_tickers_by_tag_404_message_carries_tag_context():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.get_tickers_by_tag("top-movers")

    assert "tag=top-movers" in str(exc_info.value)


# ---------------------------------------------------------------------------
# get_symbol_from_instrument_url — context: {"instrument_url": url}
# ---------------------------------------------------------------------------


def test_get_symbol_from_instrument_url_404_message_carries_instrument_url():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    bad_url = "https://api.robinhood.com/instruments/abc-xyz/"
    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.get_symbol_from_instrument_url(bad_url)

    assert f"instrument_url={bad_url}" in str(exc_info.value)
