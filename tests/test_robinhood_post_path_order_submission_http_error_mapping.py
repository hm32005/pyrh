# coding=utf-8
"""HTTP status-code -> exception mapping for POST-path order submission
methods on ``pyrh.robinhood.Robinhood``.

Closes investment-system-docs issue #147.

Background
----------
Issue #148 (PR #13) wired the shared ``_raise_for_http_error`` dispatcher
onto the two ``self.get_url(...)`` call sites in ``cancel_order`` and
introduced :class:`RobinhoodOrderSubmissionError` for 4xx fallbacks. It
was scoped to GET paths only — the POST (write-path) call sites in the
order-submission methods were left unwrapped and still raised
``ValueError`` on HTTPError.

This module wires the same dispatcher onto all 5 POST call sites:

    * ``submit_sell_order`` -- ``self.post(urls.orders(), data=payload)``
    * ``submit_buy_order``  -- ``self.post(urls.orders(), data=payload)``
    * ``place_order``       -- ``self.post(urls.orders(), data=payload)``
    * ``cancel_order`` str-branch  -- ``self.post(order["cancel"])`` retry
    * ``cancel_order`` dict-branch -- ``self.post(order["cancel"])`` retry

Reuses :class:`RobinhoodOrderSubmissionError` introduced by #148; no new
exception class is needed.

Contract (per-site)
-------------------
When the POST call raises ``requests.HTTPError``:

    * 5xx                         -> ``RobinhoodServerError``
    * 429                         -> ``RobinhoodRateLimitError`` (Retry-After)
    * 4xx (other)                 -> ``RobinhoodOrderSubmissionError``
    * HTTPError w/ no ``.response`` -> ``RobinhoodOrderSubmissionError`` (defensive)

MUST NOT raise plain ``ValueError`` on any of these paths (the legacy
contract that #148 already broke on the GET paths).

Idempotency caveat
------------------
When a POST order-submission returns 5xx, the caller MUST verify whether
the order actually went through (idempotency key + order-status query).
The dispatcher converts 5xx to ``RobinhoodServerError`` but DOES NOT
retry automatically — adding retry here would risk duplicate orders.
This is documented in the ``RobinhoodOrderSubmissionError`` docstring.
"""
import ast
from pathlib import Path
from unittest.mock import patch

import pytest
import requests


# ---------------------------------------------------------------------------
# helpers (mirrors the #148 cancel_order test module)
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


# Parametrization helper: drives every error-mapping test across all 5 POST
# sites. Each entry is (site_label, invoker_fn). The invoker patches the
# minimum surface needed to reach ``self.post(...)`` and then triggers it
# with the site-specific fake that raises the given ``HTTPError``.


def _invoke_submit_sell_order(rh, http_err):
    """Drive ``submit_sell_order`` to its ``self.post`` site."""
    fake_quote = {"bid_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_quote", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.submit_sell_order(
            instrument_url="https://api.robinhood.com/instruments/XYZ/",
            symbol="XYZ",
            order_type="market",
            time_in_force="gfd",
            trigger="immediate",
            quantity=1,
            side="sell",
        )


def _invoke_submit_buy_order(rh, http_err):
    """Drive ``submit_buy_order`` to its ``self.post`` site."""
    fake_quote = {"ask_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_quote", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.submit_buy_order(
            instrument_url="https://api.robinhood.com/instruments/XYZ/",
            symbol="XYZ",
            order_type="market",
            time_in_force="gfd",
            trigger="immediate",
            quantity=1,
            side="buy",
        )


def _invoke_place_order(rh, http_err):
    """Drive ``place_order`` to its ``self.post`` site."""
    fake_quote = {"bid_price": "10.00", "last_trade_price": "10.00"}
    fake_account = {"url": "https://api.robinhood.com/accounts/ACC/"}

    def fake_post(self, *args, **kwargs):
        raise http_err

    from pyrh.robinhood import Transaction

    with patch("pyrh.robinhood.Robinhood.quote_data", lambda self, s: fake_quote), \
         patch("pyrh.robinhood.Robinhood.get_account", lambda self: fake_account), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.place_order(
            instrument={
                "url": "https://api.robinhood.com/instruments/XYZ/",
                "symbol": "XYZ",
            },
            quantity=1,
            price=10.0,
            transaction=Transaction.BUY,
            trigger="immediate",
            order="market",
            time_in_force="gfd",
        )


def _invoke_cancel_order_str_branch_post(rh, http_err):
    """Drive ``cancel_order`` str-branch to its inner ``self.post`` retry site.

    The outer ``self.post(order["cancel"])`` sits inside a try/except that
    retries on HTTPError, then the inner retry raises the ValueError that
    this PR replaces with the dispatcher. To reach the inner site, make
    BOTH posts raise (the outer is swallowed by its own except, the inner
    is what escapes).
    """
    fake_order = {"cancel": "https://api.robinhood.com/orders/abc/cancel/"}

    def fake_get_url(self, *args, **kwargs):
        return fake_order

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.cancel_order("abc-123-order-id")


def _invoke_cancel_order_dict_branch_post(rh, http_err):
    """Drive ``cancel_order`` dict-branch to its inner ``self.post`` retry site."""
    fake_order = {"cancel": "https://api.robinhood.com/orders/abc/cancel/"}

    def fake_get_url(self, *args, **kwargs):
        return fake_order

    def fake_post(self, *args, **kwargs):
        raise http_err

    with patch("pyrh.robinhood.Robinhood.get_url", fake_get_url), \
         patch("pyrh.robinhood.Robinhood.post", fake_post):
        rh.cancel_order({"id": "abc-123-order-id"})


POST_SITES = [
    ("submit_sell_order", _invoke_submit_sell_order),
    ("submit_buy_order", _invoke_submit_buy_order),
    ("place_order", _invoke_place_order),
    ("cancel_order_str_branch", _invoke_cancel_order_str_branch_post),
    ("cancel_order_dict_branch", _invoke_cancel_order_dict_branch_post),
]


# ---------------------------------------------------------------------------
# 5xx  ->  RobinhoodServerError    (4 statuses x 5 sites = 20 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_post_methods_5xx_raises_RobinhoodServerError(site_label, invoke, status):
    from pyrh.exceptions import RobinhoodServerError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodServerError) as exc_info:
        invoke(rh, _http_error(status))

    # The bug being fixed: previously raised ValueError (cancel_order POST
    # sites) or leaked raw HTTPError (submit/place order POST sites).
    assert not isinstance(exc_info.value, ValueError)
    assert str(status) in str(exc_info.value)


# ---------------------------------------------------------------------------
# 4xx  ->  RobinhoodOrderSubmissionError    (3 statuses x 5 sites = 15 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
@pytest.mark.parametrize("status", [400, 403, 404])
def test_post_methods_4xx_raises_RobinhoodOrderSubmissionError(
    site_label, invoke, status
):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        invoke(rh, _http_error(status))

    # Must NOT be plain ValueError — that's the legacy contract this PR
    # breaks (for cancel_order POST sites) and establishes (for submit/place).
    assert not isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# 429  ->  RobinhoodRateLimitError (with + without Retry-After x 5 = 10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_429_with_retry_after(site_label, invoke):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        invoke(rh, _http_error(429, headers={"Retry-After": "17"}))

    assert not isinstance(exc_info.value, ValueError)
    assert getattr(exc_info.value, "retry_after", None) == 17


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_429_without_retry_after(site_label, invoke):
    from pyrh.exceptions import RobinhoodRateLimitError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodRateLimitError) as exc_info:
        invoke(rh, _http_error(429))

    assert getattr(exc_info.value, "retry_after", "sentinel") is None


# ---------------------------------------------------------------------------
# HTTPError with no .response  ->  RobinhoodOrderSubmissionError  (5 cases)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("site_label,invoke", POST_SITES)
def test_post_methods_no_response_raises_fallback(site_label, invoke):
    from pyrh.exceptions import RobinhoodOrderSubmissionError

    rh = _fresh_robinhood()

    with pytest.raises(RobinhoodOrderSubmissionError) as exc_info:
        invoke(rh, requests.exceptions.HTTPError("boom -- no response attached"))

    assert not isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# Surface-scan AST guard (twin of the get_url guard in
# ``test_robinhood_phase_c_and_142_http_error_mapping.py``).
# ---------------------------------------------------------------------------


# Methods on ``Robinhood`` that are intentionally NOT wrapped in a
# ``try/except requests.HTTPError`` dispatcher on their ``self.post(...)``
# call sites. Each entry requires a justification comment.
EXEMPT_UNWRAPPED_POST_METHODS: frozenset = frozenset()


def test_no_unwrapped_self_post_call_sites_on_robinhood_class():
    """Surface scan: no ``Robinhood`` method may call ``self.post(...)``
    outside a ``try`` block unless explicitly allowlisted.

    Twin of ``test_no_unwrapped_get_url_call_sites_on_robinhood_class``
    from the #142/#144 surface-scan guard, extended to the write path.
    Every ``self.post(...)`` call site must live inside a ``try`` block
    whose handler dispatches via ``_raise_for_http_error(...,
    fallback_exc=RobinhoodOrderSubmissionError)`` OR the method name must
    be added to ``EXEMPT_UNWRAPPED_POST_METHODS`` with a justification.
    """
    source = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("pyrh/robinhood.py")
        .read_text()
    )
    tree = ast.parse(source)

    robinhood_class = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "Robinhood"
        ),
        None,
    )
    assert robinhood_class is not None, "Robinhood class not found in robinhood.py"

    def _is_self_post_call(node: ast.AST) -> bool:
        """True iff ``node`` is ``self.post(...)``."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr != "post":
            return False
        value = func.value
        if not isinstance(value, ast.Name):
            return False
        return value.id == "self"

    def _inside_try(method: ast.FunctionDef, target: ast.Call) -> bool:
        """True iff ``target`` is a descendant of some ``ast.Try`` node
        whose body lives inside ``method``."""
        for node in ast.walk(method):
            if isinstance(node, ast.Try):
                for child in ast.walk(node):
                    if child is target:
                        return True
        return False

    def _has_direct_dispatcher_call(method: ast.FunctionDef) -> bool:
        """True iff method body directly invokes ``_raise_for_http_error``."""
        for node in ast.walk(method):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "_raise_for_http_error":
                    return True
        return False

    offenders = []
    for method in ast.walk(robinhood_class):
        if not isinstance(method, ast.FunctionDef):
            continue
        if method.name in EXEMPT_UNWRAPPED_POST_METHODS:
            continue
        has_dispatcher = _has_direct_dispatcher_call(method)
        for node in ast.walk(method):
            if not _is_self_post_call(node):
                continue
            if _inside_try(method, node):
                continue
            if has_dispatcher:
                continue
            offenders.append((method.name, node.lineno))

    if offenders:
        formatted = "\n".join(
            f"  - {name} at line {lineno}" for name, lineno in offenders
        )
        pytest.fail(
            "Unwrapped self.post(...) call sites found on Robinhood class "
            "(issue #147 POST-path dispatcher):\n"
            f"{formatted}\n\n"
            "Each call site must either be inside a ``try/except "
            "requests.HTTPError`` block that invokes "
            "``_raise_for_http_error(e, fallback_exc=RobinhoodOrderSubmissionError)``, "
            "or the method name must be added to "
            "``EXEMPT_UNWRAPPED_POST_METHODS`` above with a "
            "justification comment explaining why it is intentionally "
            "unwrapped."
        )
