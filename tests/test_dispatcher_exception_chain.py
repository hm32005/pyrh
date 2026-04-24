# coding=utf-8
"""Exception-chain test for the HTTP-error dispatcher (issue #127).

Issue #127 — debuggability: the dispatcher previously used
``raise ... from None`` on all four dispatch sites (5xx / 429 / auth / fallback).
The ``from None`` idiom was copied from the ``_try_refresh`` auth-refresh path,
where it was chosen to prevent credential leakage via chained HTTP exception
context. Quote / options / portfolio endpoints don't carry credentials in
HTTP error context — ``from e`` wins here because it preserves the
upstream traceback chain for debugging without any credential-leak risk.

This test pins the contract: every dispatcher raise must chain from the
original ``requests.HTTPError`` (``exc.__cause__ is err``), NOT suppress
it (``exc.__suppress_context__ is True`` and ``__cause__ is None``).
"""
import pytest
import requests


def _http_error(status_code, headers=None):
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    return requests.exceptions.HTTPError(response=resp)


def _invoke(status, headers=None):
    """Run the dispatcher on ``status`` and return (raised-exception, original-err).

    Returns the raised exception (e.g. RobinhoodServerError) plus the input
    HTTPError so the caller can assert ``raised.__cause__ is original``.
    """
    from pyrh.robinhood import _raise_for_http_error

    original = _http_error(status, headers=headers)
    try:
        _raise_for_http_error(original)
    except Exception as raised:
        return raised, original
    raise AssertionError("dispatcher did not raise")


# ---------------------------------------------------------------------------
# Chain preserved: __cause__ is the original HTTPError on all four branches
# ---------------------------------------------------------------------------


def test_5xx_chains_from_original_httperror():
    """5xx branch must use ``from e``, preserving the traceback chain."""
    raised, original = _invoke(503)
    assert raised.__cause__ is original, (
        f"RobinhoodServerError must chain from the original HTTPError; "
        f"got __cause__={raised.__cause__!r}"
    )


def test_429_chains_from_original_httperror():
    raised, original = _invoke(429, headers={"Retry-After": "3"})
    assert raised.__cause__ is original


def test_401_auth_chains_from_original_httperror():
    """Issue #140 auth branch must also chain (introduced in same bundle)."""
    raised, original = _invoke(401)
    assert raised.__cause__ is original


def test_404_fallback_chains_from_original_httperror():
    raised, original = _invoke(404)
    assert raised.__cause__ is original


# ---------------------------------------------------------------------------
# Negative guard: __cause__ must NOT be None (would be None under ``from None``)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,headers",
    [(500, None), (429, {"Retry-After": "1"}), (401, None), (404, None)],
)
def test_dispatcher_sets_non_null_cause(status, headers):
    """``from None`` sets ``__cause__ = None`` (and suppress=True);
    ``from e`` sets ``__cause__ = e``. This parametrized negative guard
    pins the replacement across every branch — a regression that uses
    ``from None`` anywhere in the dispatcher would immediately fail on
    at least one parametrize case.
    """
    raised, original = _invoke(status, headers=headers)
    assert raised.__cause__ is original, (
        f"Dispatcher must chain from the HTTPError (use ``from e``, not ``from None``); "
        f"got __cause__={raised.__cause__!r}"
    )
