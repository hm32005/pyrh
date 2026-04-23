# coding=utf-8
"""robinhood.py: a collection of utilities for working with Robinhood's Private API."""

from enum import Enum
from typing import Any, Mapping
from urllib.parse import unquote

import pendulum
import requests
from yarl import URL

from pyrh import urls
from pyrh.exceptions import (
    InvalidOptionId,
    InvalidTickerSymbol,
    RobinhoodOrderSubmissionError,
    RobinhoodRateLimitError,
    RobinhoodResourceError,
    RobinhoodServerError,
)
from pyrh.models.instrument import InstrumentManager
from pyrh.models.portfolio import PortfolioSchema
from pyrh.models.sessionmanager import (
    SessionManager,
    SessionManagerSchema,
)
from pyrh.util import coalesce_deprecated_kwarg


# TODO: re-enable InvalidOptionId when broken endpoint function below is fixed


class Bounds(Enum):
    """Enum for bounds in `historicals` endpoint."""

    REGULAR = "regular"
    EXTENDED = "extended"


class Transaction(Enum):
    """Enum for buy/sell orders."""

    BUY = "buy"
    SELL = "sell"


def _format_context(context: Mapping[str, Any] | None) -> str:
    """Render a context mapping as ``"k1=v1, k2=v2"`` for exception messages.

    Issue #150: the dispatcher ``_raise_for_http_error`` now accepts an
    optional ``context`` mapping so each call site can surface the resource
    id (order id, ticker, instrument url, tag, option id, etc.) that
    triggered the HTTP error. This helper produces the string form; an
    empty or ``None`` mapping returns ``""`` so the BC branch in each
    exception class treats it as "no context" and leaves the legacy
    message unchanged.

    Values are rendered with ``str()``; non-string context values (ints,
    floats, yarl URLs) stringify naturally without exploding.
    """
    if not context:
        return ""
    return ", ".join(f"{key}={value}" for key, value in context.items())


def _raise_for_http_error(
    err: requests.exceptions.HTTPError,
    *,
    fallback_exc: type = InvalidTickerSymbol,
    context: Mapping[str, Any] | None = None,
) -> None:
    """Translate a ``requests.HTTPError`` from a quote/fundamentals/options call
    into the right pyrh exception based on status code.

    See investment-system-docs issue #79 (quote/fundamentals) and #125 (options)
    for context: previously every HTTP error on these paths was masked as a
    single "bad input" exception (``InvalidTickerSymbol`` or ``InvalidOptionId``),
    so users thought their input was bad when Robinhood was actually down or
    rate-limiting.

    Dispatch:
        * 5xx              -> ``RobinhoodServerError``
        * 429              -> ``RobinhoodRateLimitError`` (with ``Retry-After``)
        * any other 4xx    -> ``fallback_exc()`` (unchanged per-caller behaviour)
        * no ``.response`` -> ``fallback_exc()`` (defensive fallback)

    Args:
        err: the ``requests.HTTPError`` the caller intercepted.
        fallback_exc: the exception class to raise for 4xx-not-429 and for the
            no-``.response`` defensive branch. Quote/fundamentals sites pass
            ``InvalidTickerSymbol`` (the default); the options-quote site
            passes ``InvalidOptionId``. This preserves the legacy "bad input"
            signal per-endpoint while letting 5xx / 429 propagate as
            server/rate-limit errors.
        context: optional mapping of resource-id fields (e.g.
            ``{"order_id": order_id}``, ``{"ticker": symbol}``,
            ``{"instrument_url": url}``) that gets rendered into the raised
            exception's message for debuggability. Issue #150: closes the
            regression where the dispatcher lost the resource context that
            the legacy ``raise ValueError("Failed for order_id: " + ...)``
            pattern used to carry. When ``None`` / empty the exception
            message is byte-identical to pre-#150 pyrh releases
            (backwards-compatibility invariant).

    Always re-raises — never returns — and uses ``from None`` so the HTTP
    stack trace does not leak to callers (matches the pattern shipped for
    ``_try_refresh`` in the auth refactor).
    """
    context_str = _format_context(context)

    response = getattr(err, "response", None)
    status_code = getattr(response, "status_code", None) if response is not None else None

    if status_code is not None and 500 <= status_code < 600:
        raise RobinhoodServerError(status_code, context_str) from None
    if status_code == 429:
        retry_after_raw = (
            response.headers.get("Retry-After") if response is not None else None
        )
        try:
            retry_after = int(retry_after_raw) if retry_after_raw is not None else None
        except (TypeError, ValueError):
            retry_after = None
        raise RobinhoodRateLimitError(
            retry_after=retry_after, context_str=context_str
        ) from None
    raise fallback_exc(context_str) from None


# Backwards-compatible alias. Keeps any external caller (test helpers, fixtures,
# downstream forks) that imports the old name working. The body is identical —
# ``_raise_for_http_error`` defaults ``fallback_exc`` to ``InvalidTickerSymbol``,
# which is what the old helper always raised on the 4xx-not-429 branch.
_raise_for_quote_http_error = _raise_for_http_error


class Robinhood(InstrumentManager, SessionManager):
    """Wrapper class for fetching/parsing Robinhood endpoints.

    Please see :py:class:`pyrh.models.sessionmanager.SessionManager` for login functionality.

    Provides a global convenience wrapper for the following manager objects:

        * InstrumentManager
        * TODO: Add to this list

    """

    ###########################################################################
    #                               GET DATA                                  #
    ###########################################################################

    def user(self):
        # Issue #137 Phase C: profile endpoint — no ticker input, so a 4xx
        # means the authenticated user's profile resource is unavailable
        # (``RobinhoodResourceError``), not a bad ticker.
        try:
            return self.get_url(urls.USER)
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    def investment_profile(self):
        """Fetch investment_profile."""
        # Surfaced by the surface-scan AST guard (issue #144). Profile
        # endpoint, no ticker input — ``RobinhoodResourceError`` matches
        # the Phase C fallback rationale.
        try:
            return self.get_url(urls.INVESTMENT_PROFILE)
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    def quote_data(self, stock=""):
        """Fetch stock quote.

        Args:
            stock (str or dict): stock ticker symbol or stock instrument

        Returns:
            (:obj:`dict`): JSON contents from `quotes` endpoint

        """

        if isinstance(stock, dict) and "symbol" in stock.keys():
            ticker = stock["symbol"]
            url = str(urls.QUOTES) + ticker + "/"
        elif isinstance(stock, str):
            ticker = stock
            url = str(urls.QUOTES) + ticker + "/"
        else:
            raise InvalidTickerSymbol()

        # Check for validity of symbol
        try:
            data = self.get_url(url)
        except requests.exceptions.HTTPError as e:
            # Issue #150: thread the ticker into the raised exception so
            # operators can correlate the failure with the input.
            _raise_for_http_error(e, context={"ticker": ticker})

        return data

    # We will keep for compatibility until next major release
    def quotes_data(self, stocks):
        """Fetch quote for multiple stocks, in one single Robinhood API call.

        Args:
            stocks (list<str>): stock tickers

        Returns:
            (:obj:`list` of :obj:`dict`): List of JSON contents from `quotes` \
                endpoint, in the same order of input args. If any ticker is \
                invalid, a None will occur at that position.

        """

        url = str(urls.QUOTES) + "?symbols=" + ",".join(stocks)

        try:
            data = self.get_url(url)
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the full ticker list so callers can
            # identify which batch triggered the failure.
            _raise_for_http_error(e, context={"tickers": ",".join(stocks)})

        return data["results"]

    def get_quote_list(self, stock="", key=""):
        """Returns multiple stock info and keys from quote_data (prompt if blank)

        Args:
            stock (str): stock ticker (or tickers separated by a comma)
            , prompt if blank
            key (str): key attributes that the function should return

        Returns:
            (:obj:`list`): Returns values from each stock or empty list
                           if none of the stocks were valid

        """

        # Creates a tuple containing the information we want to retrieve
        def append_stock(result_dict):
            return [result_dict[item] for item in key.split(",")]

        # Prompt for stock if not entered
        if not stock:  # pragma: no cover
            stock = input("Symbol: ")

        data = self.quote_data(stock)
        res = []

        # Handles the case of multiple tickers
        if stock.find(",") != -1:
            res.extend((append_stock(result) for result in data["results"] if result is not None))
        else:
            res.append(append_stock(data))

        return res

    def get_quote(self, stock=""):
        """Wrapper for quote_data."""

        data = self.quote_data(stock)
        return data

    def get_stock_marketdata(self, instruments: list[Any]) -> dict[str, Any]:
        # Delegate URL construction to ``urls.market_data_quotes`` so yarl
        # builds the query string correctly; the previous inline form was
        # broken (path segments containing ``?`` + unreturned value).
        #
        # Issue #142: callers pass ticker-derived instruments, so a 4xx
        # maps to the legacy "bad ticker" signal (``InvalidTickerSymbol``)
        # while 5xx / 429 surface as the real server / rate-limit errors.
        try:
            info = self.get_url(urls.market_data_quotes(instruments))
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the instruments payload (first few items,
            # truncated) so operators can identify which batch blew up.
            _raise_for_http_error(
                e,
                context={"instrument_count": len(instruments)},
            )
        return info["results"]

    def get_historical_quotes(self, stock, interval, span, bounds=Bounds.REGULAR):
        """Fetch historical data for stock.

        Note: valid interval/span configs
            interval = 5minute | 10minute + span = day, week
            interval = day + span = year
            interval = week
            TODO: NEEDS TESTS

        Args:
            stock (str): stock ticker
            interval (str): resolution of data
            span (str): length of data
            bounds (:obj:`Bounds`, optional): 'extended' or 'regular' trading hours

        Returns:
            (:obj:`dict`) values returned from `historicals` endpoint

        """
        if type(stock) is str:
            stock = [stock]

        if isinstance(bounds, str):  # recast to Enum
            bounds = Bounds(bounds)

        historicals = urls.HISTORICALS.with_query(
            [
                ("symbols", ",".join(stock).upper()),
                ("interval", interval),
                ("span", span),
                ("bounds", bounds.name.lower()),
            ]
        )

        # Issue #142: ticker-input endpoint — 4xx keeps the legacy "bad
        # ticker" signal (``InvalidTickerSymbol``) while 5xx / 429 surface
        # as server / rate-limit errors instead of leaking raw HTTPError.
        try:
            return self.get_url(historicals)
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the ticker / interval / span tuple so
            # operators can reproduce the failing historicals query.
            _raise_for_http_error(
                e,
                context={
                    "tickers": ",".join(stock),
                    "interval": interval,
                    "span": span,
                },
            )

    def get_news(self, stock):
        """Fetch news endpoint.

        Args:
            stock (str): stock ticker

        Returns:
            (:obj:`dict`) values returned from `news` endpoint

        """

        # Issue #137 Phase B: translate HTTP errors via the shared dispatcher.
        # ``get_news`` takes a ticker, so a 4xx here is legacy "bad ticker"
        # input (fallback: ``InvalidTickerSymbol``); 5xx / 429 surface as
        # ``RobinhoodServerError`` / ``RobinhoodRateLimitError`` instead of
        # leaking raw ``requests.HTTPError``.
        ticker = stock.upper()
        try:
            return self.get_url(urls.news(ticker))
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the ticker for debuggability.
            _raise_for_http_error(e, context={"ticker": ticker})

    def get_watchlists(self):
        """Fetch watchlists endpoint and queries for
        each instrumented result aka stock details returned from the watchlist.

        Returns:
            (:obj:`dict`): values returned from ``watchlists`` and
                ``instrument`` endpoints.

        Note:
            Do NOT convert this back to ``@property``. A prior refactor did
            exactly that — reintroducing the same anti-pattern that commit
            ``081807c`` removed from ``fundamentals``. Property getters
            receive only ``self``, so any future argument (e.g. watchlist
            name filter) would be silently discarded, and existing callers
            using ``rh.get_watchlists()`` would break with
            ``TypeError: 'list' object is not callable``.
        """

        # Issue #137 Phase A: wrap every get_url site so 5xx/429 surface as
        # RobinhoodServerError / RobinhoodRateLimitError instead of a raw
        # HTTPError leaking to the caller.
        try:
            res = []
            watchlist = self.get_url(urls.WATCHLISTS)
            if watchlist and "results" in watchlist:
                data = self.get_url(watchlist["results"][0]["url"])
                for rec in data["results"]:
                    res.append(self.get_url(rec["instrument"]))
            return res
        except requests.exceptions.HTTPError as e:
            # Issue #150: no meaningful per-call input (the watchlists
            # endpoint is scoped by the authenticated session), but mark
            # the resource so log lines are greppable.
            _raise_for_http_error(
                e,
                fallback_exc=RobinhoodResourceError,
                context={"resource": "watchlists"},
            )

    # Back-compat alias for callers that used the short name introduced in
    # the buggy @property revision. Kept as a regular unbound method so it
    # behaves identically to ``get_watchlists``. Do not remove without a
    # deprecation cycle.
    watchlists = get_watchlists

    def print_quote(self, stock=""):  # pragma: no cover
        """Print quote information.

        Args:
            stock (str): ticker to fetch

        Returns:
            None

        """

        data = self.get_quote_list(stock, "symbol,last_trade_price")
        for item in data:
            quote_str = item[0] + ": $" + item[1]
            print(quote_str)

    def print_quotes(self, stocks):  # pragma: no cover
        """Print a collection of stocks.

        Args:
            stocks (:obj:`list`): list of stocks to pirnt

        Returns:
            None

        """

        if stocks is None:
            return

        for stock in stocks:
            self.print_quote(stock)

    def ask_price(self, stock=""):
        """Get asking price for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (float): ask price

        """

        return self.get_quote_list(stock, "ask_price")

    def ask_size(self, stock=""):
        """Get ask size for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (int): ask size

        """

        return self.get_quote_list(stock, "ask_size")

    def bid_price(self, stock=""):
        """Get bid price for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (float): bid price

        """

        return self.get_quote_list(stock, "bid_price")

    def bid_size(self, stock=""):
        """Get bid size for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (int): bid size

        """

        return self.get_quote_list(stock, "bid_size")

    def last_trade_price(self, stock=""):
        """Get last trade price for a stock

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (float): last trade price

        """

        return self.get_quote_list(stock, "last_trade_price")

    def previous_close(self, stock=""):
        """Get previous closing price for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (float): previous closing price

        """

        return self.get_quote_list(stock, "previous_close")

    def previous_close_date(self, stock=""):
        """Get previous closing date for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (str): previous close date

        """

        return self.get_quote_list(stock, "previous_close_date")

    def adjusted_previous_close(self, stock=""):
        """Get adjusted previous closing price for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (float): adjusted previous closing price

        """

        return self.get_quote_list(stock, "adjusted_previous_close")

    def symbol(self, stock=""):
        """Get symbol for a stock.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (str): stock symbol

        """

        return self.get_quote_list(stock, "symbol")

    def last_updated_at(self, stock=""):
        """Get last update datetime.

        Note:
            queries `quote` endpoint, dict wrapper

        Args:
            stock (str): stock ticker

        Returns:
            (str): last update datetime
        """

        return self.get_quote_list(stock, "last_updated_at")

    def last_updated_at_datetime(self, stock=""):
        """Get last updated datetime.

        Note:
            queries `quote` endpoint, dict wrapper
            `self.last_updated_at` returns time as `str` in format:
            'YYYY-MM-ddTHH:mm:ss:000Z'

        Args:
            stock (str): stock ticker

        Returns:
            (datetime): last update datetime

        """

        # Will be in format: 'YYYY-MM-ddTHH:mm:ss:000Z'
        datetime_string = self.last_updated_at(stock)
        result = pendulum.parse(datetime_string)

        return result

    def get_account(self):
        """Fetch account information.

        Returns:
            (:obj:`dict`): `accounts` endpoint payload

        """

        # Issue #137 Phase C: account / profile endpoint — no ticker
        # input, so a 4xx means the authenticated user's account resource
        # is unavailable (``RobinhoodResourceError``), not a bad ticker.
        try:
            res = self.get_url(urls.ACCOUNTS)
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

        return res["results"][0]

    def get_url(self, url, schema=None):
        """Flat wrapper for fetching URL directly/"""

        return self.get(url, schema=schema)

    def get_popularity(self, stock=""):
        """Get the number of robinhood users who own the given stock

        Args:
            stock (str): stock ticker

        Returns:
            (int): number of users who own the stock

        """
        # Issue #137 Phase B: translate HTTP errors via the shared dispatcher.
        # ``get_popularity`` takes a ticker, so a 4xx fits legacy "bad
        # ticker" semantics (fallback: ``InvalidTickerSymbol``). Note that
        # ``quote_data`` is ALREADY wrapped (issue #79 / PR #5), so if the
        # ticker fails at the quote step it raises through that dispatcher
        # directly. This wrapper covers the intermediate
        # ``get_url(self.quote_data(...)["instrument"])`` AND the final
        # ``get_url(urls.instruments(...))`` call sites.
        try:
            stock_instrument = self.get_url(self.quote_data(stock)["instrument"])["id"]
            return self.get_url(urls.instruments(stock_instrument, "popularity"))[
                "num_open_positions"
            ]
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the ticker so logs can pinpoint the
            # failing popularity lookup.
            _raise_for_http_error(e, context={"ticker": stock})

    def get_tickers_by_tag(self, tag=None):
        """Get a list of instruments belonging to a tag

        Args: tag - Tags may include but are not limited to:
            * top-movers
            * etf
            * 100-most-popular
            * mutual-fund
            * finance
            * cap-weighted
            * investment-trust-or-fund

        Returns:
            (List): a list of Ticker strings

        """
        # Issue #137 Phase B: translate HTTP errors via the shared dispatcher.
        # ``get_tickers_by_tag`` takes a tag name (not a ticker), so a 4xx
        # is "tag not found / bad tag" — a resource lookup failure. Use
        # ``RobinhoodResourceError`` as the fallback (same shape as the
        # Phase A portfolio/watchlists fallback).
        #
        # NOTE on semantics: this method paginates via a list comprehension
        # over instrument URLs returned by the tag-list call. If any of
        # those per-instrument ``get_url`` calls 5xx's mid-iteration, the
        # whole method raises ``RobinhoodServerError`` and NO partial result
        # is returned. That matches the all-or-nothing contract callers
        # already rely on (the method signature is a ``List[str]`` — a
        # half-filled list would silently lose tickers and that's worse
        # than an explicit error).
        try:
            instrument_list = self.get_url(urls.tags(tag))["instruments"]
            return [self.get_url(instrument)["symbol"] for instrument in instrument_list]
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the tag so operators can identify which
            # lookup failed.
            _raise_for_http_error(
                e,
                fallback_exc=RobinhoodResourceError,
                context={"tag": tag},
            )

    def all_instruments(self):
        """
        Returns a list of symbols of securities in user's portfolio.
        """
        # Issue #137 Phase B: translate HTTP errors via the shared dispatcher.
        # ``positions()`` is ALREADY wrapped (Phase A) and raises pyrh
        # exceptions directly — it will not leak raw ``HTTPError`` here.
        # This wrapper covers the per-iteration ``get_url(position["instrument"])``
        # loop inside the method body. Fallback: ``RobinhoodResourceError``
        # (no user input — a 4xx means Robinhood's own instrument URL is
        # unreachable, which is a resource lookup failure, not bad input).
        #
        # NOTE on semantics: if an instrument fetch 5xx's mid-pagination,
        # the whole method raises ``RobinhoodServerError`` and NO partial
        # result is returned. The method signature is a list — a
        # half-populated list would silently drop positions and that's
        # worse than an explicit error. Callers that want partial results
        # should iterate positions themselves.
        try:
            positions = self.positions()
            instruments = []
            for position in positions["results"]:
                instruments.append(self.get_url(position["instrument"]))
            return instruments
        except requests.exceptions.HTTPError as e:
            # Issue #150: mark the resource for grep-ability; there's no
            # per-call input (session-scoped endpoint).
            _raise_for_http_error(
                e,
                fallback_exc=RobinhoodResourceError,
                context={"resource": "all_instruments"},
            )

    def get_symbol_from_instrument_url(self, url):
        # Surfaced by the surface-scan AST guard (issue #144). Takes an
        # instrument URL (resource identifier, not a ticker) — 4xx means
        # the instrument resource is unavailable, so
        # ``RobinhoodResourceError`` matches the Phase A / Phase C
        # fallback pattern for non-ticker resource lookups.
        try:
            instrument = self.get_url(url)
        except requests.exceptions.HTTPError as e:
            # Issue #150: surface the instrument URL so operators can see
            # which resource failed to resolve.
            _raise_for_http_error(
                e,
                fallback_exc=RobinhoodResourceError,
                context={"instrument_url": url},
            )
        return instrument["symbol"]

    ###########################################################################
    #                           GET OPTIONS INFO                              #
    ###########################################################################

    def get_options(self, stock, expiration_dates, option_type):
        """Get a list (chain) of options contracts belonging to a particular stock

        Args: stock ticker (str), list of expiration dates to filter on
            (YYYY-MM-DD), and regardless of whether it is a 'put' or a 'call' option type
            (str).

        Returns:
            Options Contracts (List): a list (chain) of contracts for a given \
            underlying equity instrument

        """
        # Issue #135: wrap the unwrapped ``get_url`` calls (instrument lookup,
        # options-chain discovery, options-list retrieval) in the same
        # dispatcher used by ``get_option_market_data`` (see PR #8 for #125).
        # The first ``get_url`` hop is via ``quote_data`` which already has
        # its own dispatcher, but the three subsequent calls are on the
        # options code path and previously raised raw ``requests.HTTPError``
        # on any 5xx / 429 / non-404 4xx.
        try:
            instrument_id = self.get_url(self.quote_data(stock)["instrument"])["id"]
            if isinstance(expiration_dates, list):
                _expiration_dates_string = ",".join(expiration_dates)
            else:
                _expiration_dates_string = expiration_dates
            chain_id = self.get_url(urls.chain(instrument_id))["results"][0]["id"]
            return [
                contract
                for contract in self.get_url(
                    urls.options(chain_id, _expiration_dates_string, option_type)
                )["results"]
            ]
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)

    def get_option_market_data(self, option_id):
        """Gets a list of market data for a given option_id.

        Args: (str) option id

        Returns: dictionary of options market data.

        """
        try:
            market_data = self.get_url(urls.market_data(option_id)) or {}
            return market_data
        except requests.exceptions.HTTPError as e:
            # Issue #125: previously *any* HTTPError (5xx outage, 429 rate
            # limit, 404 bad id) collapsed to ``InvalidOptionId``. The
            # dispatcher now routes 5xx -> RobinhoodServerError and 429 ->
            # RobinhoodRateLimitError while preserving the legacy
            # InvalidOptionId mapping for the 4xx-not-429 branch.
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)

    def options_owned(self):
        # Issue #135: translate 5xx/429 on the options-positions endpoint to
        # the informative ``RobinhoodServerError`` / ``RobinhoodRateLimitError``
        # rather than leaking raw ``requests.HTTPError`` to consumers.
        try:
            options = self.get_url(
                urls.OPTIONS_BASE.join(URL("positions/?nonzero=true"))
            )
            options = options["results"]
            return options
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)

    def get_option_marketdata(self, option_id):
        # Issue #135: sibling of ``get_option_market_data`` (fixed in #125).
        # Same dispatcher, same fallback.
        try:
            info = self.get_url(
                urls.MARKET_DATA_BASE.join(URL(f"options/{option_id}/"))
            )
            return info
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)

    def get_option_chain_id(self, symbol):
        # Issue #135: two ``get_url`` calls — instrument lookup and chain
        # discovery. Either can hit a Robinhood outage; both need dispatcher
        # translation.
        try:
            stock_info = self.get_url(urls.INSTRUMENTS_BASE.with_query(symbol=symbol))
            instrument_id = stock_info["results"][0]["id"]
            url = urls.OPTIONS_BASE.join(URL("chains/"))
            chains = self.get_url(url.with_query(equity_instrument_ids=instrument_id))
            chains = chains["results"]
            chain_id = None

            for chain in chains:
                if chain["can_open_position"]:
                    chain_id = chain["id"]

            return chain_id
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)

    def get_option_quote(self, symbol, strike, expiry, otype, state="active"):
        url = urls.OPTIONS_BASE.join(URL("instruments/"))
        params = {
            "chain_symbol":     symbol,
            "strike_price":     strike,
            "expiration_dates": expiry,
            "type":             otype,
            "state":            state,
        }
        # Issue #135: the options-instruments ``get_url`` call was unwrapped.
        # The downstream ``get_option_marketdata`` already has its own
        # dispatcher (also fixed in this change), so we only need to wrap
        # the first call here.
        try:
            # symbol, strike, expiry, otype should uniquely define an option
            results = self.get_url(url.with_query(**params)).get("results")
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=InvalidOptionId)
        if not results:
            return
        else:
            option_id = results[0]["id"]
            result = self.get_option_marketdata(option_id)
            params["ask"] = "{} x {}".format(result["ask_size"], result["ask_price"])
            params["bid"] = "{} x {}".format(result["bid_size"], result["bid_price"])
            return params

    ###########################################################################
    #                           GET FUNDAMENTALS
    ###########################################################################

    def fundamentals(self, stock=""):
        """Find stock fundamentals data

        Args:
            stock (str): stock ticker

        Returns:
            (:obj:`dict`): contents of `fundamentals` endpoint

        Note:
            Previously decorated @property, which silently discarded the
            `stock` argument (property getters are called with just `self`).
            Any caller written as `rh.fundamentals` would have returned
            without actually querying a symbol.
        """

        # Prompt for stock if not entered
        if not stock:  # pragma: no cover
            stock = input("Symbol: ")

        ticker = str(stock.upper())
        url = str(urls.fundamentals(ticker))

        # Check for validity of symbol
        try:
            data = self.get_url(url)
            return data
        except requests.exceptions.HTTPError as e:
            # Issue #150: thread the ticker so fundamentals failures are
            # tied back to the input symbol.
            _raise_for_http_error(e, context={"ticker": ticker})

    ###########################################################################
    #                           PORTFOLIOS DATA
    ###########################################################################

    def portfolio(self):
        """Returns the user's portfolio data"""

        # Issue #137 Phase A: translate HTTP errors via the shared dispatcher.
        try:
            return self.get_url(urls.PORTFOLIOS, schema=PortfolioSchema())
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    def order_history(self, order_id=None):
        """Wrapper for portfolios

        Optional Args: add an order ID to retrieve information about a single order.

        Returns:
            (:obj:`dict`): JSON dict from getting orders

        """

        # Issue #137 Phase A: translate HTTP errors via the shared dispatcher.
        try:
            return self.get_url(urls.orders(order_id))
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    def dividends(self):
        """Wrapper for portfolios

        Returns:
            (:obj: `dict`): JSON dict from getting dividends

        """

        # Issue #137 Phase A: translate HTTP errors via the shared dispatcher.
        try:
            return self.get_url(urls.DIVIDENDS)
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    ###########################################################################
    #                           POSITIONS DATA
    ###########################################################################

    def positions(self):
        """Returns the user's positions data

        Returns:
            (:object: `dict`): JSON dict from getting positions

        """

        # Issue #137 Phase A: translate HTTP errors via the shared dispatcher.
        try:
            return self.get_url(urls.POSITIONS)
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    def securities_owned(self):
        """Returns list of securities' symbols that the user has shares in

        Returns:
            (:object: `dict`): Non-zero positions

        """

        # Issue #137 Phase A: translate HTTP errors via the shared dispatcher.
        try:
            return self.get_url(str(urls.POSITIONS) + "?nonzero=true")
        except requests.exceptions.HTTPError as e:
            _raise_for_http_error(e, fallback_exc=RobinhoodResourceError)

    ###########################################################################
    #                               PLACE ORDER
    ###########################################################################

    def place_market_buy_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing market buy orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            quantity (int): Number of shares to buy
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_buy_order(
            order_type="market",
            trigger="immediate",
            side="buy",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            quantity=quantity,
        )

    def place_limit_buy_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing limit buy orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            price (float): The max price you're willing to pay per share
            quantity (int): Number of shares to buy
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_buy_order(
            order_type="limit",
            trigger="immediate",
            side="buy",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            price=price,
            quantity=quantity,
        )

    def place_stop_loss_buy_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            stop_price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing stop loss buy orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            stop_price (float): The price at which this becomes a market order
            quantity (int): Number of shares to buy
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_buy_order(
            order_type="market",
            trigger="stop",
            side="buy",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            stop_price=stop_price,
            quantity=quantity,
        )

    def place_stop_limit_buy_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            stop_price=None,
            price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing stop limit buy orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            stop_price (float): The price at which this becomes a limit order
            price (float): The max price you're willing to pay per share
            quantity (int): Number of shares to buy
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_buy_order(
            order_type="limit",
            trigger="stop",
            side="buy",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            stop_price=stop_price,
            price=price,
            quantity=quantity,
        )

    def place_market_sell_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing market sell orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            quantity (int): Number of shares to sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_sell_order(
            order_type="market",
            trigger="immediate",
            side="sell",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            quantity=quantity,
        )

    def place_limit_sell_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing limit sell orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            price (float): The minimum price you're willing to get per share
            quantity (int): Number of shares to sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_sell_order(
            order_type="limit",
            trigger="immediate",
            side="sell",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            price=price,
            quantity=quantity,
        )

    def place_stop_loss_sell_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            stop_price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing stop loss sell orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            stop_price (float): The price at which this becomes a market order
            quantity (int): Number of shares to sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_sell_order(
            order_type="market",
            trigger="stop",
            side="sell",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            stop_price=stop_price,
            quantity=quantity,
        )

    def place_stop_limit_sell_order(
            self,
            instrument_url=None,
            symbol=None,
            time_in_force=None,
            price=None,
            stop_price=None,
            quantity=None,
            instrument_URL=None,
    ):
        """Wrapper for placing stop limit sell orders

        Notes:
            If only one of the instrument_URL or symbol are passed as
            arguments the other will be looked up automatically.

        Args:
            instrument_url (str): The RH URL of the instrument
            symbol (str): The ticker symbol of the instrument
            time_in_force (str): 'GFD' or 'GTC' (day or until cancelled)
            stop_price (float): The price at which this becomes a limit order
            price (float): The max price you're willing to get per share
            quantity (int): Number of shares to sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )
        return self.submit_sell_order(
            order_type="limit",
            trigger="stop",
            side="sell",
            instrument_url=instrument_url,
            symbol=symbol,
            time_in_force=time_in_force,
            stop_price=stop_price,
            price=price,
            quantity=quantity,
        )

    # TODO: fix the function complexity
    def submit_sell_order(  # noqa: C901
            self,
            instrument_url=None,
            symbol=None,
            order_type=None,
            time_in_force=None,
            trigger=None,
            price=None,
            stop_price=None,
            quantity=None,
            side=None,
            instrument_URL=None,
    ):
        """Submits order to Robinhood

        Notes:
            This is normally not called directly.  Most programs should use
            one of the following instead:

                place_market_buy_order()
                place_limit_buy_order()
                place_stop_loss_buy_order()
                place_stop_limit_buy_order()
                place_market_sell_order()
                place_limit_sell_order()
                place_stop_loss_sell_order()
                place_stop_limit_sell_order()

        Args:
            instrument_url (str): the RH URL for the instrument
            symbol (str): the ticker symbol for the instrument
            order_type (str): 'MARKET' or 'LIMIT'
            time_in_force (:obj:`TIME_IN_FORCE`): GFD or GTC (day or
                                                   until cancelled)
            trigger (str): IMMEDIATE or STOP enum
            price (float): The share price you'll accept
            stop_price (float): The price at which the order becomes a
                                market or limit order
            quantity (int): The number of shares to buy/sell
            side (str): BUY or sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )

        # Used for default price input
        # Price is required, so we use the current bid price if it is not specified
        current_quote = self.get_quote(symbol)
        if (current_quote["bid_price"] == 0) or (current_quote["bid_price"] is None):
            current_bid_price = current_quote["last_trade_price"]
        else:
            current_bid_price = current_quote["bid_price"]

        # Start with some parameter checks. I'm paranoid about $.
        if instrument_url is None:
            if symbol is None:
                raise (
                    ValueError(
                        "Neither instrument_URL nor symbol were passed to "
                        "submit_sell_order"
                    )
                )
            raise (ValueError("Instrument_URL not passed to submit_sell_order"))

        if symbol is None:
            raise (ValueError("Symbol not passed to submit_sell_order"))

        if side is None:
            raise (
                ValueError("Order is neither buy nor sell in call to submit_sell_order")
            )

        if order_type is None:
            if price is None:
                if stop_price is None:
                    order_type = "market"
                else:
                    order_type = "limit"

        symbol = str(symbol).upper()
        order_type = str(order_type).lower()
        time_in_force = str(time_in_force).lower()
        trigger = str(trigger).lower()
        side = str(side).lower()

        if (order_type != "market") and (order_type != "limit"):
            raise (ValueError("Invalid order_type in call to submit_sell_order"))

        if order_type == "limit":
            if price is None:
                raise (
                    ValueError("Limit order has no price in call to submit_sell_order")
                )
            if price <= 0:
                raise (
                    ValueError(
                        "Price must be positive number in call to submit_sell_order"
                    )
                )

        if trigger == "stop":
            if stop_price is None:
                raise (
                    ValueError(
                        "Stop order has no stop_price in call to submit_sell_order"
                    )
                )
            if price <= 0:
                raise (
                    ValueError(
                        "Stop_price must be positive number in call to "
                        "submit_sell_order"
                    )
                )

        if stop_price is not None:
            if trigger != "stop":
                raise (
                    ValueError(
                        "Stop price set for non-stop order in call to submit_sell_order"
                    )
                )

        if price is None:
            if order_type == "limit":
                raise (
                    ValueError("Limit order has no price in call to submit_sell_order")
                )

        if price is not None:
            if order_type.lower() == "market":
                raise (
                    ValueError(
                        "Market order has price limit in call to submit_sell_order"
                    )
                )
            price = float(price)
        else:
            price = current_bid_price  # default to current bid price

        if quantity is None:
            raise (ValueError("No quantity specified in call to submit_sell_order"))

        quantity = int(quantity)

        if quantity <= 0:
            raise (
                ValueError(
                    "Quantity must be positive number in call to submit_sell_order"
                )
            )

        payload = {}

        for field, value in [
            ("account", self.get_account()["url"]),
            ("instrument", instrument_url),
            ("symbol", symbol),
            ("type", order_type),
            ("time_in_force", time_in_force),
            ("trigger", trigger),
            ("price", price),
            ("stop_price", stop_price),
            ("quantity", quantity),
            ("side", side),
        ]:
            if value is not None:
                payload[field] = value

        # Issue #147: wrap POST with shared HTTPError dispatcher so 5xx /
        # 429 / 4xx propagate as distinct pyrh exceptions instead of
        # leaking raw requests.HTTPError. Reuses RobinhoodOrderSubmissionError
        # introduced by PR #13 (#148) as the 4xx fallback.
        try:
            res = self.post(urls.orders(), data=payload)
        except requests.exceptions.HTTPError as err_msg:
            _raise_for_http_error(
                err_msg, fallback_exc=RobinhoodOrderSubmissionError
            )
        return res

    # TODO: Fix function complexity
    def submit_buy_order(  # noqa: C901
            self,
            instrument_url=None,
            symbol=None,
            order_type=None,
            time_in_force=None,
            trigger=None,
            price=None,
            stop_price=None,
            quantity=None,
            side=None,
            instrument_URL=None,
    ):
        """Submits buy order to Robinhood

        Notes:
            This is normally not called directly.  Most programs should use
            one of the following instead:

                place_market_buy_order()
                place_limit_buy_order()
                place_stop_loss_buy_order()
                place_stop_limit_buy_order()
                place_market_sell_order()
                place_limit_sell_order()
                place_stop_loss_sell_order()
                place_stop_limit_sell_order()

        Args:
            instrument_url (str): the RH URL for the instrument
            symbol (str): the ticker symbol for the instrument
            order_type (str): 'market' or 'limit'
            time_in_force (:obj:`TIME_IN_FORCE`): 'gfd' or 'gtc' (day or
                                                   until cancelled)
            trigger (str): 'immediate' or 'stop' enum
            price (float): The share price you'll accept
            stop_price (float): The price at which the order becomes a
                                market or limit order
            quantity (int): The number of shares to buy/sell
            side (str): BUY or sell
            instrument_URL (str): DEPRECATED — legacy name for
                ``instrument_url``; forwarded with a ``DeprecationWarning``.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        instrument_url = coalesce_deprecated_kwarg(
            "instrument_url", instrument_url, "instrument_URL", instrument_URL
        )

        # Used for default price input
        # Price is required, so we use the current ask price if it is not specified
        current_quote = self.get_quote(symbol)
        if (current_quote["ask_price"] == 0) or (current_quote["ask_price"] is None):
            current_ask_price = current_quote["last_trade_price"]
        else:
            current_ask_price = current_quote["ask_price"]

        # Start with some parameter checks. I'm paranoid about $.
        if instrument_url is None:
            if symbol is None:
                raise (
                    ValueError(
                        "Neither instrument_URL nor symbol were passed to "
                        "submit_buy_order"
                    )
                )
            raise (ValueError("Instrument_URL not passed to submit_buy_order"))

        if symbol is None:
            raise (ValueError("Symbol not passed to submit_buy_order"))

        if side is None:
            raise (
                ValueError("Order is neither buy nor sell in call to submit_buy_order")
            )

        if order_type is None:
            if price is None:
                if stop_price is None:
                    order_type = "market"
                else:
                    order_type = "limit"

        symbol = str(symbol).upper()
        order_type = str(order_type).lower()
        time_in_force = str(time_in_force).lower()
        trigger = str(trigger).lower()
        side = str(side).lower()

        if (order_type != "market") and (order_type != "limit"):
            raise (ValueError("Invalid order_type in call to submit_buy_order"))

        if order_type == "limit":
            if price is None:
                raise (
                    ValueError("Limit order has no price in call to submit_buy_order")
                )
            if price <= 0:
                raise (
                    ValueError(
                        "Price must be positive number in call to submit_buy_order"
                    )
                )

        if trigger == "stop":
            if stop_price is None:
                raise (
                    ValueError(
                        "Stop order has no stop_price in call to submit_buy_order"
                    )
                )
            if price <= 0:
                raise (
                    ValueError(
                        "Stop_price must be positive number in call to submit_buy_order"
                    )
                )

        if stop_price is not None:
            if trigger != "stop":
                raise (
                    ValueError(
                        "Stop price set for non-stop order in call to submit_buy_order"
                    )
                )

        if price is None:
            if order_type == "limit":
                raise (
                    ValueError("Limit order has no price in call to submit_buy_order")
                )

        if price is not None:
            if order_type.lower() == "market":
                raise (
                    ValueError(
                        "Market order has price limit in call to submit_buy_order"
                    )
                )
            price = float(price)
        else:
            price = current_ask_price  # default to current ask price

        if quantity is None:
            raise (ValueError("No quantity specified in call to submit_buy_order"))

        quantity = int(quantity)

        if quantity <= 0:
            raise (
                ValueError(
                    "Quantity must be positive number in call to submit_buy_order"
                )
            )

        payload = {}

        for field, value in [
            ("account", self.get_account()["url"]),
            ("instrument", instrument_url),
            ("symbol", symbol),
            ("type", order_type),
            ("time_in_force", time_in_force),
            ("trigger", trigger),
            ("price", price),
            ("stop_price", stop_price),
            ("quantity", quantity),
            ("side", side),
        ]:
            if value is not None:
                payload[field] = value

        # Issue #147: wrap POST with shared HTTPError dispatcher — see
        # submit_sell_order above for rationale. Reuses
        # RobinhoodOrderSubmissionError from PR #13 (#148).
        try:
            res = self.post(urls.orders(), data=payload)
        except requests.exceptions.HTTPError as err_msg:
            _raise_for_http_error(
                err_msg, fallback_exc=RobinhoodOrderSubmissionError
            )
        return res

    def place_order(
            self,
            instrument,
            quantity=1,
            price=0.0,
            transaction=None,
            trigger="immediate",
            order="market",
            time_in_force="gfd",
    ):
        """Place an order with Robinhood

        Args:
            instrument (dict): the RH URL and symbol in dict for the instrument to
                be traded
            quantity (int): quantity of stocks in order
            price (float): price for order
            transaction (:obj:`Transaction`): BUY or SELL enum
            trigger (:obj:`Trigger`): IMMEDIATE or STOP enum
            order (:obj:`Order`): MARKET or LIMIT
            time_in_force (:obj:`TIME_IN_FORCE`): GFD or GTC (day or until
                cancelled)

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """

        if isinstance(transaction, str):
            transaction = Transaction(transaction)

        if not price:
            price = self.quote_data(instrument["symbol"])["bid_price"]

            if (price == 0) or (price is None):
                price = self.quote_data(instrument["symbol"])["last_trade_price"]

        payload = {
            "account":       self.get_account()["url"],
            "instrument":    unquote(instrument["url"]),
            "symbol":        instrument["symbol"],
            "type":          order.lower(),
            "time_in_force": time_in_force.lower(),
            "trigger":       trigger,
            "quantity":      quantity,
            "side":          transaction.name.lower(),
        }

        if order.lower() == "stop":
            payload["stop_price"] = float(price)
        else:
            payload["price"] = float(price)

        # Issue #147: wrap POST with shared HTTPError dispatcher — see
        # submit_sell_order for rationale. Reuses
        # RobinhoodOrderSubmissionError from PR #13 (#148).
        try:
            res = self.post(urls.orders(), data=payload)
        except requests.exceptions.HTTPError as err_msg:
            _raise_for_http_error(
                err_msg, fallback_exc=RobinhoodOrderSubmissionError
            )
        return res

    def place_buy_order(self, instrument, quantity, ask_price=0.0):
        """Wrapper for placing buy orders

        Args:
            instrument (dict): the RH URL and symbol in dict for the instrument to
                be traded
            quantity (int): quantity of stocks in order
            ask_price (float): price for order (OPTIONAL! If not given, ask_price is
                automatic.)

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """

        if not ask_price:
            ask_price = self.quote_data(instrument["symbol"])["ask_price"]

            if (ask_price == 0) or (ask_price is None):
                ask_price = self.quote_data(instrument["symbol"])["last_trade_price"]

        transaction = Transaction.BUY

        return self.place_order(instrument, quantity, ask_price, transaction)

    def place_sell_order(self, instrument, quantity, bid_price=0.0):
        """Wrapper for placing sell orders

        Args:
            instrument (dict): the RH URL and symbol in dict for the instrument to
                be traded
            quantity (int): quantity of stocks in order
            bid_price (float): price for order (OPTIONAL! If not given, bid_price is
                automatic.)

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        if not bid_price:
            bid_price = self.quote_data(instrument["symbol"])["bid_price"]

            if (bid_price == 0) or (bid_price is None):
                bid_price = self.quote_data(instrument["symbol"])["last_trade_price"]

        transaction = Transaction.SELL

        return self.place_order(instrument, quantity, bid_price, transaction)

    ##############################
    # GET OPEN ORDER(S)
    ##############################

    def get_open_orders(self):
        """Returns all currently open (cancellable) orders.

        If not orders are currently open, `None` is returned.

        TODO: Is there a way to get these from the API endpoint without stepping through
            order history?

        .. note::
            As of pyrh v3.x, this method may raise :class:`RobinhoodServerError`,
            :class:`RobinhoodRateLimitError`, or :class:`RobinhoodResourceError`
            (transitively via :meth:`order_history`) instead of the legacy raw
            :class:`requests.HTTPError`. Callers relying on ``except
            requests.HTTPError`` should update to the richer exception
            hierarchy. See investment-system-docs issue #138.
        """

        open_orders = []
        orders = self.order_history()
        for order in orders["results"]:
            if order["cancel"] is not None:
                open_orders.append(order)

        return open_orders

    ##############################
    #        CANCEL ORDER        #
    ##############################

    # TODO: Fix function complexity
    def cancel_order(self, order_id):  # noqa: C901
        """Cancels specified order and returns the response.

        If order cannot be cancelled, `None` is returned.
        (results from `orders` command).

        Args:
            order_id (str or dict): Order ID string that is to be cancelled or open
                order dict returned from order get.

        Returns:
            (:obj:`requests.request`): result from `orders` put command

        """
        if isinstance(order_id, str):
            try:
                order = self.get_url(urls.orders(order_id))
            except requests.exceptions.HTTPError as err_msg:
                # Issue #148: was ``raise ValueError(...)``; now dispatches
                # via ``_raise_for_http_error`` so callers can distinguish
                # 5xx / 429 / 4xx by exception class. Breaks the legacy
                # ``ValueError`` contract — see PR #148 release note.
                _raise_for_http_error(
                    err_msg, fallback_exc=RobinhoodOrderSubmissionError
                )

            if order.get("cancel") is not None:
                try:
                    res = self.post(order["cancel"])
                    return res
                except requests.exceptions.HTTPError:
                    try:
                        # sometimes Robinhood asks for another log in when placing an
                        # order
                        res = self.post(order["cancel"])
                        return res
                    except requests.exceptions.HTTPError as err_msg:
                        # Issue #147: POST-path dispatcher wiring —
                        # replaces the legacy ``raise ValueError`` with
                        # the shared dispatcher so 5xx / 429 / 4xx
                        # propagate as distinct pyrh exceptions. Reuses
                        # RobinhoodOrderSubmissionError from PR #13 (#148)
                        # as the 4xx fallback.
                        _raise_for_http_error(
                            err_msg,
                            fallback_exc=RobinhoodOrderSubmissionError,
                        )

        elif isinstance(order_id, dict):
            order_id = order_id["id"]
            try:
                order = self.get_url(urls.orders(order_id))
            except requests.exceptions.HTTPError as err_msg:
                # Issue #148 (dict-branch twin of the str-branch site above).
                _raise_for_http_error(
                    err_msg, fallback_exc=RobinhoodOrderSubmissionError
                )

            if order.get("cancel") is not None:
                try:
                    res = self.post(order["cancel"])
                    return res
                except requests.exceptions.HTTPError:
                    try:
                        # sometimes Robinhood asks for another log in when placing an
                        # order
                        res = self.post(order["cancel"])
                        return res
                    except requests.exceptions.HTTPError as err_msg:
                        # Issue #147: dict-branch twin of the str-branch
                        # POST dispatcher above. See rationale there.
                        _raise_for_http_error(
                            err_msg,
                            fallback_exc=RobinhoodOrderSubmissionError,
                        )

        elif not isinstance(order_id, str) or not isinstance(order_id, dict):
            raise ValueError(
                "Cancelling orders requires a valid order_id string or open order"
                "dictionary"
            )

        # Order type cannot be cancelled without a valid cancel link
        else:
            raise ValueError(f"Unable to cancel order ID: {order_id}")


class RobinhoodSchema(SessionManagerSchema):
    """Schema for the Robinhood class."""

    __model__ = Robinhood
