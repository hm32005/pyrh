# coding=utf-8
"""Backward-compatibility tests for the ``urls.build_*`` → short-name rename.

Historical context (commit ``1cdb2ac`` — "Harish's tweaks", Nov 7 2024):
The upstream pyrh API used nine ``build_*`` helper names in ``pyrh/urls.py``:

    build_challenge, build_ach, build_orders, build_news, build_fundamentals,
    build_tags, build_chain, build_options, build_market_data

That commit renamed them all to their short forms (``challenge``, ``ach``,
``orders``, ``news``, ``fundamentals``, ``tags``, ``chain``, ``options``,
``market_data``) and dropped the old names with no shim. Any external caller
doing ``from pyrh.urls import build_challenge`` hits ``ImportError``.

Issue #185 requires a BC (backward-compatibility) shim that accepts the old
name, emits a ``DeprecationWarning``, and forwards the call to the new
function. These tests lock in the shim.

The new-name behavior is already covered by ``tests/test_urls.py``; these
tests cover only the deprecated aliases.
"""
import warnings

import pytest


# (old_name, new_name, args-tuple used to exercise the shim).
# Args are chosen to match the non-optional signatures of each helper.
RENAMES = [
    ("build_challenge", "challenge", ("abc-123",)),
    ("build_ach", "ach", ("relationships",)),
    ("build_orders", "orders", ()),
    ("build_news", "news", ("TSLA",)),
    ("build_fundamentals", "fundamentals", ("TSLA",)),
    ("build_tags", "tags", ("popular",)),
    ("build_chain", "chain", ("instrument-id-1",)),
    ("build_options", "options", ("chain-1", "2030-01-01", "call")),
    ("build_market_data", "market_data", ("option-id-1",)),
]


@pytest.mark.parametrize(
    ("old_name", "new_name", "args"),
    RENAMES,
    ids=[r[0] for r in RENAMES],
)
def test_old_build_name_is_importable(old_name, new_name, args):
    """``from pyrh.urls import <old_name>`` must succeed."""
    from pyrh import urls

    assert hasattr(urls, old_name), (
        f"pyrh.urls is missing BC alias {old_name!r}"
    )


@pytest.mark.parametrize(
    ("old_name", "new_name", "args"),
    RENAMES,
    ids=[r[0] for r in RENAMES],
)
def test_old_build_name_emits_deprecation_warning(old_name, new_name, args):
    """Calling the old name must emit ``DeprecationWarning`` naming both names."""
    from pyrh import urls

    old_fn = getattr(urls, old_name)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        old_fn(*args)

    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, (
        f"{old_name}: expected DeprecationWarning, got {caught}"
    )
    msg = str(deprecation[0].message)
    assert old_name in msg, f"{old_name}: warning should name old symbol, got {msg!r}"
    assert new_name in msg, f"{old_name}: warning should name new symbol, got {msg!r}"


@pytest.mark.parametrize(
    ("old_name", "new_name", "args"),
    RENAMES,
    ids=[r[0] for r in RENAMES],
)
def test_old_build_name_returns_same_url_as_new_name(old_name, new_name, args):
    """The old-name call must return the same URL the new name returns."""
    from pyrh import urls

    old_fn = getattr(urls, old_name)
    new_fn = getattr(urls, new_name)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old_result = old_fn(*args)
    new_result = new_fn(*args)

    assert str(old_result) == str(new_result), (
        f"{old_name}({args!r}) -> {old_result!r} did not match "
        f"{new_name}({args!r}) -> {new_result!r}"
    )
