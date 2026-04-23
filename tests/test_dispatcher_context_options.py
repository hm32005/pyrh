# coding=utf-8
"""Context propagation for the options dispatcher call sites (issue #150).

Group B covers: ``get_options``, ``get_option_market_data``, ``options_owned``,
``get_option_marketdata``, ``get_option_chain_id``, ``get_option_quote``.

Representative subset tested here: ``get_option_market_data`` (option_id
context), ``get_option_chain_id`` (symbol context), ``get_options`` (stock +
type + expiry context).
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
# get_option_market_data — context: {"option_id": option_id}
# ---------------------------------------------------------------------------


def test_get_option_market_data_404_message_carries_option_id():
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId) as exc_info:
            rh.get_option_market_data("opt-xyz-789")

    assert "option_id=opt-xyz-789" in str(exc_info.value)


def test_get_option_market_data_500_message_carries_option_id():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(500)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.get_option_market_data("opt-500")

    msg = str(exc_info.value)
    assert "500" in msg
    assert "option_id=opt-500" in msg


# ---------------------------------------------------------------------------
# get_option_chain_id — context: {"symbol": symbol}
# ---------------------------------------------------------------------------


def test_get_option_chain_id_404_message_carries_symbol():
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId) as exc_info:
            rh.get_option_chain_id("TSLA")

    assert "symbol=TSLA" in str(exc_info.value)


# ---------------------------------------------------------------------------
# get_options — context: {"stock", "option_type"}
# ---------------------------------------------------------------------------


def test_get_options_404_message_carries_stock_and_type():
    """``get_options`` calls quote_data first; we let that succeed and fail
    on the subsequent get_url so we exit through the get_options dispatcher
    (not quote_data's) and see the stock+option_type context."""
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_quote_data(self, stock):
        return {"instrument": "https://api.robinhood.com/instruments/abc/"}

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.quote_data", fake_quote_data):
        with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
            with pytest.raises(InvalidOptionId) as exc_info:
                rh.get_options("TSLA", ["2024-12-20"], "call")

    msg = str(exc_info.value)
    assert "stock=TSLA" in msg
    assert "option_type=call" in msg


# ---------------------------------------------------------------------------
# options_owned — session-scoped, marker context
# ---------------------------------------------------------------------------


def test_options_owned_404_message_carries_resource_marker():
    from pyrh.exceptions import InvalidOptionId

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(InvalidOptionId) as exc_info:
            rh.options_owned()

    assert "resource=options_owned" in str(exc_info.value)
