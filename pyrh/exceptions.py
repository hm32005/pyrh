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
