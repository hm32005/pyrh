# coding=utf-8
"""Context propagation for the POST-path dispatcher sites (issue #150).

Group D covers the order-submission / order-cancel dispatcher sites:
``submit_sell_order``, ``submit_buy_order``, ``place_order``,
``cancel_order`` (4 dispatcher calls: str + dict x {GET + retry-POST}).

Representative subset: cancel_order(str) GET-path, cancel_order(str)
retry-POST path, place_order 500-branch.
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
# cancel_order str branch — GET path carries order_id
# ---------------------------------------------------------------------------


def test_cancel_order_str_branch_get_404_message_carries_order_id():
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
            rh.cancel_order("order-cancel-abc")

    assert "order_id=order-cancel-abc" in str(exc_info.value)


# ---------------------------------------------------------------------------
# cancel_order dict branch — GET path carries order_id
# ---------------------------------------------------------------------------


def test_cancel_order_dict_branch_get_500_message_carries_order_id():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(500)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.cancel_order({"id": "order-dict-123"})

    msg = str(exc_info.value)
    assert "500" in msg
    assert "order_id=order-dict-123" in msg


# ---------------------------------------------------------------------------
# cancel_order str branch — POST retry path carries order_id
# ---------------------------------------------------------------------------


def test_cancel_order_str_branch_post_retry_5xx_message_carries_order_id():
    """After GET succeeds with a ``cancel`` URL, both POST attempts fail;
    the second failure's dispatcher should surface the order_id."""
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        return {"cancel": "https://api.robinhood.com/orders/x/cancel/"}

    def fake_post(self, url, data=None):
        raise _http_error(502)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with patch("pyrh.robinhood.Robinhood.post", fake_post):
            with pytest.raises(RobinhoodServerError) as exc_info:
                rh.cancel_order("order-retry-xyz")

    msg = str(exc_info.value)
    assert "502" in msg
    assert "order_id=order-retry-xyz" in msg


# ---------------------------------------------------------------------------
# place_order — context carries instrument symbol + quantity + side
# ---------------------------------------------------------------------------


def test_place_order_500_message_carries_context():
    from pyrh.exceptions import RobinhoodServerError
    from pyrh.robinhood import Transaction

    rh = _fresh_robinhood()

    # Stub out dependencies: quote_data returns prices, get_account gives url.
    def fake_quote_data(self, symbol):
        return {"bid_price": 100.0, "ask_price": 101.0, "last_trade_price": 100.5}

    def fake_get_account(self):
        return {"url": "https://api.robinhood.com/accounts/abc/"}

    def fake_post(self, url, data=None):
        raise _http_error(500)

    with patch("pyrh.robinhood.Robinhood.quote_data", fake_quote_data):
        with patch("pyrh.robinhood.Robinhood.get_account", fake_get_account):
            with patch("pyrh.robinhood.Robinhood.post", fake_post):
                with pytest.raises(RobinhoodServerError) as exc_info:
                    rh.place_order(
                        {
                            "url": "https://api.robinhood.com/instruments/xyz/",
                            "symbol": "TSLA",
                        },
                        quantity=5,
                        transaction=Transaction.BUY,
                    )

    msg = str(exc_info.value)
    assert "500" in msg
    # Issue #160: context key normalised from "symbol" to "ticker" across
    # all dispatcher sites for naming consistency.
    assert "ticker=TSLA" in msg
    assert "quantity=5" in msg
