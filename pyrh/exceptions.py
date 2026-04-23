# coding=utf-8
"""Exceptions: custom exceptions for library"""


class PyrhException(Exception):
    """Wrapper for custom robinhood library exceptions."""

    pass


class PyrhValueError(ValueError, PyrhException):
    """Value Error for the pyrh library."""


class InvalidCacheFile(PyrhException):
    """Error when the cache config file is found to be invalid."""

    pass


class InvalidOperation(PyrhException):
    """An invalid operation was requsted to be performed."""

    pass


class AuthenticationError(PyrhException):
    """Error when trying to login to robinhood."""

    pass


class InvalidTickerSymbol(PyrhException):
    """When an invalid ticker (stock symbol) is given/"""

    pass


class InvalidOptionId(PyrhException):
    """When an invalid option id is given/"""

    pass


class RobinhoodServerError(PyrhException):
    """Robinhood backend returned a 5xx status (outage / upstream error).

    Raised instead of ``InvalidTickerSymbol`` when the HTTP response carries a
    5xx code, so callers don't waste time second-guessing their ticker input
    when the real problem is that Robinhood is down. See investment-system-docs
    issue #79.
    """

    def __init__(self, status_code: int, message: str | None = None) -> None:
        self.status_code = status_code
        if message is None:
            message = (
                f"Robinhood returned {status_code} — server error, try again later."
            )
        super().__init__(message)


class RobinhoodResourceError(PyrhException):
    """Robinhood returned a 4xx status on a user-resource endpoint.

    Raised on trading / portfolio / watchlist endpoints where the legacy
    ``InvalidTickerSymbol`` fallback doesn't fit semantically — those
    endpoints don't take a ticker, so a "bad ticker" signal would confuse
    callers. ``RobinhoodResourceError`` covers 4xx-not-429 responses on
    user-owned resources such as ``portfolio``, ``order_history``,
    ``dividends``, ``positions``, ``securities_owned``, and
    ``get_watchlists``.

    See investment-system-docs issue #137 Phase A for context: Phase A wires
    the shared HTTPError dispatcher onto those 6 methods, and needed a
    semantically-neutral 4xx fallback distinct from ``InvalidTickerSymbol``
    (quotes/fundamentals) and ``InvalidOptionId`` (options).
    """

    pass


class RobinhoodOrderSubmissionError(PyrhException):
    """4xx errors during order submission, modification, or cancellation.

    Introduced by investment-system-docs issue #148 to replace the legacy
    ``raise ValueError`` pattern in ``Robinhood.cancel_order`` so callers
    can distinguish permanent 4xx failures (bad order id, account
    restriction, insufficient funds) from transient 5xx / 429 failures
    (server outage, rate limit) by exception class rather than by parsing
    string messages.

    Note: when retrying a 5xx on order-submission callers MUST verify
    whether the original request actually went through (idempotency key +
    order-status query). The dispatcher converts 5xx to
    ``RobinhoodServerError``; this class is for 4xx semantics only (e.g.
    invalid order id, account restriction, insufficient funds).

    Inherits from ``PyrhException`` (i.e. bare ``Exception``), NOT
    ``ValueError``. The break with the legacy ``ValueError`` contract is
    intentional: callers doing ``except ValueError`` on cancel-order /
    submit-order results will need to migrate to this class (or the
    broader ``PyrhException``). See PR description for #148 for release
    notes.

    Paired with issue #147 (POST-path order-submission dispatcher), which
    will reuse this class for ``submit_buy_order``, ``submit_sell_order``,
    and ``place_order``.
    """

    pass


class RobinhoodRateLimitError(PyrhException):
    """Robinhood returned HTTP 429 (rate-limited).

    Distinct from ``InvalidTickerSymbol`` — the user's input is fine; the
    client is sending too many requests. ``retry_after`` (if provided by the
    server via the ``Retry-After`` header) is exposed as an int of seconds
    so callers can back off appropriately. Retry logic itself is a consumer
    concern (see issue #79 scope note).
    """

    def __init__(
        self, retry_after: int | None = None, message: str | None = None
    ) -> None:
        self.retry_after = retry_after
        if message is None:
            hint = (
                f" (retry after {retry_after}s)" if retry_after is not None else ""
            )
            message = f"Robinhood rate limit hit (HTTP 429){hint}."
        super().__init__(message)
