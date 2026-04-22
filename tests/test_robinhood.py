# coding=utf-8
"""Unit tests for ``pyrh.robinhood.Robinhood`` public API shapes.

These are deliberately thin — they pin the *shape* of the API (is it a
method? is it a property? does it accept an argument?) rather than the
full request/response roundtrip. Each test exists specifically to catch
a previously-shipped regression where a method was converted to a
``@property``, silently discarding arguments or breaking call sites.
"""
from unittest.mock import patch


def test_fundamentals_accepts_stock_argument():
    """``rh.fundamentals("TSLA")`` must be a callable method, not a property.

    The earlier bug (commit 081807c fixed it) decorated ``fundamentals`` with
    ``@property`` at the class level. Property getters receive only ``self``,
    so any caller written as ``rh.fundamentals("TSLA")`` would either raise
    ``TypeError: 'str' object is not callable`` on the returned value or
    silently run with ``stock=""`` (prompting ``input()`` in a non-TTY
    context). This regression test locks in the method shape.
    """
    from pyrh.robinhood import Robinhood

    # Class-level assertion: must NOT be a property descriptor.
    assert not isinstance(Robinhood.__dict__["fundamentals"], property), (
        "Robinhood.fundamentals must be a method, not a @property"
    )

    rh = Robinhood.__new__(Robinhood)  # bypass __init__ (needs auth)
    captured = {}

    def fake_get_url(self, url):
        captured["url"] = url
        return {"ok": True}

    with patch.object(Robinhood, "get_url", fake_get_url):
        result = rh.fundamentals("TSLA")

    assert result == {"ok": True}
    assert str(captured["url"]).endswith("/fundamentals/TSLA/")


def test_watchlists_is_method_not_property():
    """``Robinhood.watchlists`` must be a plain method, not a ``@property``.

    The motivating bug: commit 081807c removed the same ``@property``
    anti-pattern from ``fundamentals``. A subsequent refactor reintroduced
    it on ``watchlists`` — silently dropping the public ``get_watchlists``
    method and breaking external callers. This test pins the method shape.
    """
    from pyrh.robinhood import Robinhood

    assert not isinstance(Robinhood.__dict__["watchlists"], property), (
        "Robinhood.watchlists must be a method, not a @property"
    )

    # Back-compat alias must also exist.
    assert callable(getattr(Robinhood, "get_watchlists", None)), (
        "Robinhood.get_watchlists alias must remain callable for external callers"
    )
