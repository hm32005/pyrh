# coding=utf-8
"""Tests for the Nummus (crypto) endpoint wrappers.

Phantom-cash audit (2026-04-26): the Robinhood crypto sub-account lives on
``https://nummus.robinhood.com/portfolios/`` and ``.../holdings/``. These
endpoints are stable but had zero coverage in pyrh — investment-system
"total wealth" views had to either ignore crypto entirely or duplicate the
HTTP plumbing.

These tests pin the new ``crypto_portfolio()`` and ``crypto_holdings()``
wrappers: they hit the Nummus host (not ``api.robinhood.com``) and return
the dict payload as-is.
"""
from __future__ import annotations

from unittest.mock import patch


def _fresh_robinhood():
    """Construct a Robinhood instance without going through ``__init__``.

    The tests in this repo use this idiom (see
    ``test_dispatcher_context_get_path.py``) to avoid the auth flow when
    they only need to exercise a single method.
    """
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


def test_crypto_portfolio_calls_nummus_portfolios_endpoint():
    """``crypto_portfolio()`` must hit
    ``https://nummus.robinhood.com/portfolios/`` (the Nummus host), not
    the main ``api.robinhood.com/portfolios/`` endpoint."""
    rh = _fresh_robinhood()
    expected = {"results": [{"equity": "5.39"}]}

    captured = {}

    def fake_get_url(self, url, schema=None):
        captured["url"] = str(url)
        return expected

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.crypto_portfolio()

    assert captured["url"] == "https://nummus.robinhood.com/portfolios/"
    assert result == expected


def test_crypto_holdings_calls_nummus_holdings_endpoint():
    """``crypto_holdings()`` must hit
    ``https://nummus.robinhood.com/holdings/``."""
    rh = _fresh_robinhood()
    expected = {
        "results": [
            {"currency": {"code": "BTC"}, "quantity": "0.001"},
        ]
    }

    captured = {}

    def fake_get_url(self, url, schema=None):
        captured["url"] = str(url)
        return expected

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        result = rh.crypto_holdings()

    assert captured["url"] == "https://nummus.robinhood.com/holdings/"
    assert result == expected


def test_crypto_portfolio_returns_dict_payload_unchanged():
    """The wrapper must not transform the response — callers expect the
    raw Nummus payload (no schema, since pyrh has none for Nummus today)."""
    rh = _fresh_robinhood()
    payload = {
        "results": [
            {
                "equity": "5.39",
                "extended_hours_equity": "5.40",
                "market_value": "5.39",
            }
        ]
    }

    with patch("pyrh.robinhood.Robinhood.get_url", lambda self, url, schema=None: payload):
        result = rh.crypto_portfolio()

    assert result is payload  # identity, not just equality


def test_crypto_holdings_returns_dict_payload_unchanged():
    rh = _fresh_robinhood()
    payload = {
        "results": [
            {"currency": {"code": "BTC"}, "quantity": "0.001"},
            {"currency": {"code": "USDC"}, "quantity": "100.00"},
        ]
    }

    with patch("pyrh.robinhood.Robinhood.get_url", lambda self, url, schema=None: payload):
        result = rh.crypto_holdings()

    assert result is payload
