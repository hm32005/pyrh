# coding=utf-8
"""Backward-compatibility tests for the ``instrument_URL`` → ``instrument_url`` rename.

Historical context (commit ``1cdb2ac`` — "Harish's tweaks"):
The upstream pyrh API used ``instrument_URL`` (mixed case) as the kwarg name
on eight ``place_*_order`` wrappers and the shared ``submit_buy_order`` /
``submit_sell_order`` entry points. That commit renamed the kwarg to
``instrument_url`` (PEP 8) across all ten public methods and dropped the
old name with no shim. Any external caller passing ``instrument_URL=...``
receives ``TypeError: unexpected keyword argument``.

Issue #80 requires a BC (backward-compatibility) shim that accepts the old
kwarg name, emits a ``DeprecationWarning``, and forwards the value to the
new kwarg. Passing both names must raise ``TypeError`` to prevent silent
ambiguity.

These tests only cover the shim; the primary (new-name) behavior is
exercised by existing end-to-end tests.
"""
import warnings
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# The eight ``place_*_order`` wrappers delegate to ``submit_buy_order`` /
# ``submit_sell_order``. We verify the shim by patching the downstream
# submit method and inspecting the forwarded ``instrument_url`` kwarg.
# ---------------------------------------------------------------------------

PLACE_BUY_METHODS = [
    ("place_market_buy_order", {"time_in_force": "gfd", "quantity": 1}),
    (
        "place_limit_buy_order",
        {"time_in_force": "gfd", "price": 1.0, "quantity": 1},
    ),
    (
        "place_stop_loss_buy_order",
        {"time_in_force": "gfd", "stop_price": 1.0, "quantity": 1},
    ),
    (
        "place_stop_limit_buy_order",
        {
            "time_in_force": "gfd",
            "stop_price": 1.0,
            "price": 1.0,
            "quantity": 1,
        },
    ),
]

PLACE_SELL_METHODS = [
    ("place_market_sell_order", {"time_in_force": "gfd", "quantity": 1}),
    (
        "place_limit_sell_order",
        {"time_in_force": "gfd", "price": 1.0, "quantity": 1},
    ),
    (
        "place_stop_loss_sell_order",
        {"time_in_force": "gfd", "stop_price": 1.0, "quantity": 1},
    ),
    (
        "place_stop_limit_sell_order",
        {
            "time_in_force": "gfd",
            "stop_price": 1.0,
            "price": 1.0,
            "quantity": 1,
        },
    ),
]

SENTINEL_URL = "https://api.robinhood.com/instruments/sentinel-id/"


def _make_rh():
    """Create a ``Robinhood`` instance without invoking ``__init__``.

    ``__init__`` requires live auth. The shim logic under test does not
    touch auth, so ``__new__`` is sufficient.
    """
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


@pytest.mark.parametrize(
    ("method_name", "extra_kwargs"),
    PLACE_BUY_METHODS,
    ids=[m[0] for m in PLACE_BUY_METHODS],
)
def test_place_buy_wrapper_accepts_old_instrument_URL_kwarg(method_name, extra_kwargs):
    """Old ``instrument_URL`` kwarg must be forwarded as ``instrument_url``."""
    rh = _make_rh()
    captured = {}

    def fake_submit_buy(self, **kwargs):
        captured.update(kwargs)
        return {"ok": True}

    from pyrh.robinhood import Robinhood

    with patch.object(Robinhood, "submit_buy_order", fake_submit_buy):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = getattr(rh, method_name)(
                instrument_URL=SENTINEL_URL, symbol="TSLA", **extra_kwargs
            )

    assert result == {"ok": True}
    assert captured.get("instrument_url") == SENTINEL_URL, (
        f"{method_name}: expected instrument_url={SENTINEL_URL!r}, "
        f"got {captured.get('instrument_url')!r}"
    )
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"{method_name}: expected DeprecationWarning, got {caught}"
    assert "instrument_URL" in str(deprecation[0].message)
    assert "instrument_url" in str(deprecation[0].message)


@pytest.mark.parametrize(
    ("method_name", "extra_kwargs"),
    PLACE_SELL_METHODS,
    ids=[m[0] for m in PLACE_SELL_METHODS],
)
def test_place_sell_wrapper_accepts_old_instrument_URL_kwarg(method_name, extra_kwargs):
    """Old ``instrument_URL`` kwarg must be forwarded as ``instrument_url``."""
    rh = _make_rh()
    captured = {}

    def fake_submit_sell(self, **kwargs):
        captured.update(kwargs)
        return {"ok": True}

    from pyrh.robinhood import Robinhood

    with patch.object(Robinhood, "submit_sell_order", fake_submit_sell):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = getattr(rh, method_name)(
                instrument_URL=SENTINEL_URL, symbol="TSLA", **extra_kwargs
            )

    assert result == {"ok": True}
    assert captured.get("instrument_url") == SENTINEL_URL, (
        f"{method_name}: expected instrument_url={SENTINEL_URL!r}, "
        f"got {captured.get('instrument_url')!r}"
    )
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"{method_name}: expected DeprecationWarning, got {caught}"


@pytest.mark.parametrize(
    ("method_name", "extra_kwargs"),
    PLACE_BUY_METHODS + PLACE_SELL_METHODS,
    ids=[m[0] for m in PLACE_BUY_METHODS + PLACE_SELL_METHODS],
)
def test_place_wrapper_rejects_both_old_and_new_kwarg(method_name, extra_kwargs):
    """Passing both ``instrument_URL`` and ``instrument_url`` must raise ``TypeError``.

    Prevents silent precedence ambiguity.
    """
    rh = _make_rh()
    with pytest.raises(TypeError, match="instrument_url"):
        getattr(rh, method_name)(
            instrument_URL=SENTINEL_URL,
            instrument_url="other-url",
            symbol="TSLA",
            **extra_kwargs,
        )


# ---------------------------------------------------------------------------
# ``submit_buy_order`` and ``submit_sell_order`` are the shared entry points.
# They are more complex — the shim must take effect before the rest of the
# method runs so the old kwarg can still reach the outgoing HTTP payload.
# ---------------------------------------------------------------------------


SUBMIT_METHODS = [
    ("submit_buy_order", "buy"),
    ("submit_sell_order", "sell"),
]


@pytest.mark.parametrize(("method_name", "side"), SUBMIT_METHODS, ids=[m[0] for m in SUBMIT_METHODS])
def test_submit_order_accepts_old_instrument_URL_kwarg(method_name, side):
    """The shared submit entry points must accept ``instrument_URL``."""
    rh = _make_rh()
    captured_payload = {}

    def fake_get_quote(self, stock=""):
        # submit_buy_order reads ask_price; submit_sell_order reads bid_price.
        return {"bid_price": 1.0, "ask_price": 1.0, "last_trade_price": 1.0}

    def fake_get_account(self):
        return {"url": "https://api.robinhood.com/accounts/sentinel/"}

    def fake_post(self, url, data=None, **kwargs):
        captured_payload.update(data or {})
        return {"ok": True}

    from pyrh.robinhood import Robinhood

    with patch.object(Robinhood, "get_quote", fake_get_quote), patch.object(
        Robinhood, "get_account", fake_get_account
    ), patch.object(Robinhood, "post", fake_post):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = getattr(rh, method_name)(
                instrument_URL=SENTINEL_URL,
                symbol="TSLA",
                order_type="market",
                trigger="immediate",
                time_in_force="gfd",
                quantity=1,
                side=side,
            )

    assert result == {"ok": True}
    # The payload uses key "instrument" but its value is what we passed.
    assert captured_payload.get("instrument") == SENTINEL_URL, (
        f"{method_name}: expected instrument={SENTINEL_URL!r} in payload, "
        f"got {captured_payload!r}"
    )
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, f"{method_name}: expected DeprecationWarning, got {caught}"


@pytest.mark.parametrize(("method_name", "side"), SUBMIT_METHODS, ids=[m[0] for m in SUBMIT_METHODS])
def test_submit_order_rejects_both_old_and_new_kwarg(method_name, side):
    """Submit entry points must reject ambiguous dual-kwarg calls."""
    rh = _make_rh()
    with pytest.raises(TypeError, match="instrument_url"):
        getattr(rh, method_name)(
            instrument_URL=SENTINEL_URL,
            instrument_url="other-url",
            symbol="TSLA",
            order_type="market",
            trigger="immediate",
            time_in_force="gfd",
            quantity=1,
            side=side,
        )
