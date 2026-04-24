# coding=utf-8
"""Backward-compatibility tests for Robinhood method / kwarg renames (#186).

Historical context (commit ``1cdb2ac`` — "Harish's tweaks", Nov 7 2024):
Four public ``Robinhood`` surface-area renames landed without a BC shim:

    +--------------------------------------+------------------------------+
    | Old                                  | New                          |
    +--------------------------------------+------------------------------+
    | Robinhood.get_option_chainid()       | Robinhood.get_option_chain_id() |
    | Robinhood.get_fundamentals()         | Robinhood.fundamentals()     |
    | Robinhood.order_history(orderId=...) | order_history(order_id=...)  |
    +--------------------------------------+------------------------------+

(A fourth rename — ``get_watchlists`` → ``watchlists`` — is intentionally
NOT deprecated: commit 114b73b restored ``get_watchlists`` as the canonical
method and kept ``watchlists`` as a no-warning alias, because existing
callers used the ``get_`` form. Issue #186 is stale for that pair; both
names are supported. See ``tests/test_robinhood.py::test_watchlists_is_*``
for the primary invariant.)

Issue #186 requires a DeprecationWarning shim for the three renames above.
Method renames use a thin wrapper under the old name that warns and
forwards. The kwarg rename uses the shared ``coalesce_deprecated_kwarg``
helper (``pyrh/util/deprecation.py``) — same pattern as the
``instrument_URL`` → ``instrument_url`` shim (issue #80).
"""
import warnings
from unittest.mock import patch

import pytest


def _make_rh():
    """Construct a ``Robinhood`` instance without invoking ``__init__``.

    ``__init__`` requires live auth; the shims under test do not touch
    auth, so ``__new__`` is sufficient (same pattern as
    ``tests/test_robinhood_instrument_url_bc.py``).
    """
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


# ---------------------------------------------------------------------------
# Method rename: get_option_chainid -> get_option_chain_id
# ---------------------------------------------------------------------------


def test_get_option_chainid_exists_and_warns_and_delegates():
    """Old ``get_option_chainid`` must warn and forward to ``get_option_chain_id``."""
    from pyrh.robinhood import Robinhood

    rh = _make_rh()
    captured_args = {}

    def fake_new(self, symbol):
        captured_args["symbol"] = symbol
        return "chain-id-sentinel"

    with patch.object(Robinhood, "get_option_chain_id", fake_new):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = rh.get_option_chainid("TSLA")

    assert result == "chain-id-sentinel"
    assert captured_args == {"symbol": "TSLA"}
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"expected DeprecationWarning, got {caught}"
    msg = str(deprecation[0].message)
    assert "get_option_chainid" in msg
    assert "get_option_chain_id" in msg


# ---------------------------------------------------------------------------
# Method rename: get_fundamentals -> fundamentals
# ---------------------------------------------------------------------------


def test_get_fundamentals_exists_and_warns_and_delegates():
    """Old ``get_fundamentals`` must warn and forward to ``fundamentals``."""
    from pyrh.robinhood import Robinhood

    rh = _make_rh()
    captured_args = {}

    def fake_new(self, stock=""):
        captured_args["stock"] = stock
        return {"ok": True}

    with patch.object(Robinhood, "fundamentals", fake_new):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = rh.get_fundamentals("TSLA")

    assert result == {"ok": True}
    assert captured_args == {"stock": "TSLA"}
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"expected DeprecationWarning, got {caught}"
    msg = str(deprecation[0].message)
    assert "get_fundamentals" in msg
    assert "fundamentals" in msg


def test_get_fundamentals_forwards_default_stock_argument():
    """The shim must forward positional and keyword paths identically."""
    from pyrh.robinhood import Robinhood

    rh = _make_rh()
    captured = []

    def fake_new(self, stock=""):
        captured.append(stock)
        return None

    with patch.object(Robinhood, "fundamentals", fake_new):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            rh.get_fundamentals()
            rh.get_fundamentals("AAPL")
            rh.get_fundamentals(stock="MSFT")

    assert captured == ["", "AAPL", "MSFT"]


# ---------------------------------------------------------------------------
# Kwarg rename: order_history(orderId=...) -> order_history(order_id=...)
# ---------------------------------------------------------------------------


def test_order_history_accepts_old_orderId_kwarg():
    """``order_history(orderId=...)`` must warn and forward to ``order_id``."""
    from pyrh.robinhood import Robinhood

    rh = _make_rh()
    captured_url = {}

    def fake_get_url(self, url, schema=None):
        captured_url["url"] = str(url)
        return {"ok": True}

    with patch.object(Robinhood, "get_url", fake_get_url):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = rh.order_history(orderId="order-sentinel-123")

    assert result == {"ok": True}
    assert "order-sentinel-123" in captured_url["url"], captured_url
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"expected DeprecationWarning, got {caught}"
    msg = str(deprecation[0].message)
    assert "orderId" in msg
    assert "order_id" in msg


def test_order_history_rejects_both_orderId_and_order_id():
    """Passing both forms must raise ``TypeError``."""
    rh = _make_rh()
    with pytest.raises(TypeError, match="order_id"):
        rh.order_history(orderId="a", order_id="b")


def test_order_history_new_order_id_kwarg_does_not_warn():
    """The canonical ``order_id=`` kwarg must NOT emit a DeprecationWarning."""
    from pyrh.robinhood import Robinhood

    rh = _make_rh()

    def fake_get_url(self, url, schema=None):
        return {"ok": True}

    with patch.object(Robinhood, "get_url", fake_get_url):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            rh.order_history(order_id="ok-id")

    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert not deprecation, f"unexpected DeprecationWarning(s): {deprecation}"
