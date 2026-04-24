# coding=utf-8
"""HTTP status-code -> exception mapping for ``Robinhood.cancel_order``.

Closes investment-system-docs issue #148.

Background
----------
``cancel_order`` has two ``self.get_url(...)`` call sites (one in the
``str`` branch, one in the ``dict`` branch) that were historically wrapped
with ``try/except requests.HTTPError`` handlers that did
``raise ValueError(...)``. That dropped status-code information and
collapsed server outages, rate limits, and permanent-not-found errors
into a single ``ValueError`` — callers had no way to distinguish a
transient 5xx (retry-safe) from an invalid order id (do-not-retry).

This PR wires ``_raise_for_http_error(e, fallback_exc=RobinhoodOrderSubmissionError)``
onto both call sites, aligning cancel_order with the rest of the
dispatcher rollout (#79, #125, #135, #137 Phases A/B/C, #142).

Scope note
----------
This test module exercises the two ``self.get_url(urls.orders(order_id))``
call sites only, which is what #148 is about. The companion
``self.post(order["cancel"])`` call sites in ``cancel_order`` are
covered by issue #147 (POST-path order-submission dispatcher) in
``test_robinhood_post_path_order_submission_http_error_mapping.py``,
which reuses the ``RobinhoodOrderSubmissionError`` class introduced
by this PR.

Contract (per-branch)
---------------------
For both ``isinstance(order_id, str)`` and ``isinstance(order_id, dict)``
branches, when ``self.get_url(urls.orders(order_id))`` raises
``requests.HTTPError``:

    * 5xx                         -> ``RobinhoodServerError``
    * 429                         -> ``RobinhoodRateLimitError`` (Retry-After propagated)
    * 4xx (other)                 -> ``RobinhoodOrderSubmissionError``
    * HTTPError w/ no ``.response`` -> ``RobinhoodOrderSubmissionError`` (defensive)

MUST NOT raise plain ``ValueError`` on any of these paths.
"""
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the Phase A/B/C test modules)
# ---------------------------------------------------------------------------


def _http_error(status_code, headers=None):
    """Build a ``requests.HTTPError`` whose ``.response`` has the given status."""
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    err = requests.exceptions.HTTPError(response=resp)
    return err


def _fresh_robinhood():
    """Return a ``Robinhood`` instance bypassing ``__init__`` (no auth)."""
    from pyrh.robinhood import Robinhood

    return Robinhood.__new__(Robinhood)


# Both ``cancel_order`` branches call ``self.get_url(urls.orders(order_id))``
# first. We parametrize across both branches so every test exercises both
# call sites.
ORDER_ID_INPUTS = [
    ("str_branch", "abc-123-order-id"),
    ("dict_branch", {"id": "abc-123-order-id"}),
]


def _invoke_cancel_order(rh, order_id_input):
    return rh.cancel_order(order_id_input)


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_cancel_order_5xx_raises_RobinhoodServerError(
    branch_label, order_id_input, status
):
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodServerError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    # The bug being fixed: previously these all raised ValueError.
    assert not isinstance(exc_info.value, ValueError)
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4xx  ->  RobinhoodOrderSubmissionError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
# Issue #140: 401 / 403 now route to ``RobinhoodAuthError`` in the dispatcher
# BEFORE the per-caller fallback, so they're covered in a dedicated test
# below. This parametrize covers only non-auth 4xx codes.
@pytest.mark.parametrize("status", [400, 404])
def test_cancel_order_4xx_raises_RobinhoodOrderSubmissionError(
    branch_label, order_id_input, status
):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    # Must NOT be plain ValueError — that's the legacy contract this PR breaks.
    # Note: ``RobinhoodOrderSubmissionError`` is a subclass of
    # ``PyrhException(Exception)``, NOT ``ValueError``. If a future refactor
    # reparents it under ``ValueError`` (e.g. via ``PyrhValueError``), this
    # assertion must be revisited — the contract in this PR says callers can
    # no longer rely on ``except ValueError`` to catch cancel-order failures.
    assert not isinstance(exc_info.value, ValueError)


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
@pytest.mark.parametrize("status", [401, 403])
def test_cancel_order_401_403_raises_auth_error(
    branch_label, order_id_input, status
):
    """Issue #140: 401 / 403 must raise ``RobinhoodAuthError``, NOT
    ``RobinhoodOrderSubmissionError`` — callers need to distinguish
    session-dead (re-login) from order-rejected (fix input).
    """
    from pyrh.exceptions import RobinhoodAuthError, RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(status)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodAuthError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    assert not isinstance(exc_info.value, RobinhoodOrderSubmissionError)
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with + without Retry-After)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
def test_cancel_order_429_with_retry_after(branch_label, order_id_input):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(429, headers={"Retry-After": "17"})

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    assert not isinstance(exc_info.value, ValueError)
    assert getattr(exc_info.value, "retry_after", None) == 17


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
def test_cancel_order_429_without_retry_after(branch_label, order_id_input):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise _http_error(429)

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodRateLimitError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  RobinhoodOrderSubmissionError (defensive)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch_label,order_id_input", ORDER_ID_INPUTS)
def test_cancel_order_no_response_raises_fallback(branch_label, order_id_input):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    def fake_get_url(self, *args, **kwargs):
        raise requests.exceptions.HTTPError("boom -- no response attached")

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url):
        with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
            _invoke_cancel_order(rh, order_id_input)

    assert not isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# Exception class hierarchy sanity (so future refactors don't silently
# reparent the class under ValueError and regress the contract break).
# ---------------------------------------------------------------------------


def test_RobinhoodOrderSubmissionError_is_PyrhException_not_ValueError():
    from pyrh.exceptions import PyrhException, RobinhoodOrderSubmissionError

    assert issubclass(RobinhoodOrderSubmissionError, PyrhException)
    # The whole point of #148 is breaking the ValueError contract.
    assert not issubclass(RobinhoodOrderSubmissionError, ValueError)
