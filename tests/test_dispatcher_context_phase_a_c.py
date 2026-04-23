# coding=utf-8
"""Context propagation for the Phase A / Phase C dispatcher sites (issue #150).

Group C covers the profile / account / portfolio / order-history session-scoped
endpoints: ``user``, ``investment_profile``, ``get_account``, ``portfolio``,
``order_history``, ``dividends``, ``positions``, ``securities_owned``.

Most endpoints in this group have NO per-call input (session-scoped). They
pass a ``resource=<endpoint-name>`` marker context so log lines remain
greppable. ``order_history(order_id=...)`` is the exception — it threads the
optional order_id into the message.
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
# order_history with and without order_id
# ---------------------------------------------------------------------------


def test_order_history_with_order_id_404_message_carries_order_id():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.order_history(order_id="order-xyz-789")

    assert "order_id=order-xyz-789" in str(exc_info.value)


def test_order_history_no_order_id_404_message_carries_resource_marker():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.order_history()

    assert "resource=order_history" in str(exc_info.value)


# ---------------------------------------------------------------------------
# portfolio — session-scoped
# ---------------------------------------------------------------------------


def test_portfolio_500_message_carries_resource_marker():
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, url, schema=None):
        raise _http_error(500)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            rh.portfolio()

    msg = str(exc_info.value)
    assert "500" in msg
    assert "resource=portfolio" in msg


# ---------------------------------------------------------------------------
# user / investment_profile — Phase C profile endpoints
# ---------------------------------------------------------------------------


def test_user_404_message_carries_resource_marker():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.user()

    assert "resource=user" in str(exc_info.value)


def test_investment_profile_404_message_carries_resource_marker():
    from pyrh.exceptions import RobinhoodResourceError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        raise _http_error(404)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodResourceError) as exc_info:
            rh.investment_profile()

    assert "resource=investment_profile" in str(exc_info.value)


# ---------------------------------------------------------------------------
# positions — session-scoped
# ---------------------------------------------------------------------------


def test_positions_429_message_carries_resource_marker():
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, url):
        err = _http_error(429)
        err.response.headers.update({"Retry-After": "12"})
        raise err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            rh.positions()

    assert "resource=positions" in str(exc_info.value)
    assert exc_info.value.retry_after == 12
