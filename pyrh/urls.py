# coding=utf-8
"""Define Robinhood endpoints."""

import warnings
from functools import wraps
from typing import Callable, Optional

from yarl import URL

# TODO: All url construction should happen here, not in robinhood.py

# Base
API_BASE = URL("https://api.robinhood.com")

# General
ACCOUNTS = API_BASE / "accounts/"
ACH_BASE = API_BASE / "ach/"  # not implemented
APPLICATIONS = API_BASE / "applications/"  # not implemented
DIVIDENDS = API_BASE / "dividends/"
DOCUMENTS = API_BASE / "documents/"  # not implemented
DOCUMENT_REQUESTS = API_BASE / "upload/document_requests/"  # not implemented
FUNDAMENTALS_BASE = API_BASE / "fundamentals/"
INSTRUMENTS_BASE = API_BASE / "instruments/"
MARGIN_UPGRADES = API_BASE / "margin/upgrades/"  # not implemented
MARKETS = API_BASE / "markets/"  # not implemented
MARKET_DATA_BASE = API_BASE / "marketdata/"
NEWS_BASE = API_BASE / "midlands/news/"
NOTIFICATIONS = API_BASE / "notifications/"  # not implemented
ORDERS_BASE = API_BASE / "orders/"
PORTFOLIOS = API_BASE / "portfolios/"
POSITIONS = API_BASE / "positions/"
TAGS_BASE = API_BASE / "midlands/tags/tag/"
WATCHLISTS = API_BASE / "watchlists/"

# Options
OPTIONS_BASE = API_BASE / "options/"
OPTIONS_CHAIN_BASE = OPTIONS_BASE / "chains/"
OPTIONS_INSTRUMENTS_BASE = OPTIONS_BASE / "instruments/"

# User
USER = API_BASE / "user/"
INVESTMENT_PROFILE = USER / "investment_profile/"

# Quotes
QUOTES = API_BASE / "quotes/"
HISTORICALS = QUOTES / "historicals/"

# Auth
OAUTH_BASE: URL = API_BASE / "oauth2/"
OAUTH: URL = OAUTH_BASE / "token/"
OAUTH_REVOKE: URL = OAUTH_BASE / "revoke_token/"
MIGRATE_TOKEN: URL = OAUTH_BASE / "migrate_token/"  # not implemented
PASSWORD_RESET: URL = API_BASE / "password_reset/request/"  # not implemented
USER_MACHINE: URL = API_BASE / "pathfinder/user_machine/"
INQUIRIES: URL = API_BASE / "pathfinder/inquiries"
CHALLENGE: URL = API_BASE / "challenge"
PUSH_PROMPT_STATUS: URL = API_BASE / "push"


def challenge(challenge_id: str) -> URL:
    """Build challenge response url.

    Args:
        challenge_id: the id of the challenge passed in the oauth request flow.

    Returns:
        The constructed URL with the challenge_id embedded in teh url path.

    """
    return API_BASE / f"challenge/{challenge_id}/respond/"


def ach(option: str) -> URL:
    """
    Combination of 3 ACH endpoints. Options include:
        * iav
        * relationships
        * transfers
    """
    return ACH_BASE / "iav/auth/" if option == "iav" else ACH_BASE / f"{option}/"


def instruments(
    symbol: Optional[str] = None, query: Optional[str] = None, id_: Optional[str] = None
) -> URL:
    """Construct urls that query instruments.

    Note:
        Each of the arguments are mutually exclusive.

    Args:
        symbol: A stock ticker symbol.
        query: Keyword to search for an instrument. (might be in name or ticker)
        id_: The UUID that represents the instrument.

    Returns:
        A constructed URL with the embedded query parameter

    Raises:
        ValueError: When none of ``symbol``, ``query``, or ``id_`` is provided.
            Previously this returned ``None`` silently, causing downstream
            callers to raise ``requests.exceptions.MissingSchema: Invalid URL
            'None'`` far from the actual bug (issue #78).

    """
    # Note:
    # INSTRUMENTS_BASE/{instrument_id}/splits will not be implemented since the url is
    # embedded in the results of an individual instrument result. The same logic applies
    # for INSTRUMENTS_BASE/{instrument_id}/splits/{split_id}/
    if symbol is not None:
        return INSTRUMENTS_BASE.with_query(symbol=symbol)
    elif query is not None:
        return INSTRUMENTS_BASE.with_query(query=query)
    elif id_ is not None:
        return INSTRUMENTS_BASE / f"{id_}/"
    else:
        raise ValueError(
            "instruments() requires at least one of: symbol, query, id_"
        )


def orders(order_id: Optional[str] = None) -> URL:
    """Build endpoint to place orders.

    Args:
        order_id: the id of the order

    Returns:
        A constructed URL for a particular order or the base URL for all orders.

    """
    if order_id is not None:
        return ORDERS_BASE / f"{order_id}/"
    else:
        return ORDERS_BASE


def news(stock: str) -> URL:
    """Build news endpoint for a particular stock

    Args:
        stock: The stock ticker to build the URL

    Returns:
        A constructed URL for the input stock ticker.

    """
    return NEWS_BASE / f"{stock}/"


def fundamentals(stock: str) -> URL:
    """Build fundamentals endpoint for a particular stock

    Args:
        stock: The stock ticker to build the URL

    Returns:
        A constructed URL of the fundamentals for the input stock ticker.

    """
    return FUNDAMENTALS_BASE / f"{stock}/"


def tags(tag: str) -> URL:
    """Build endpoints for tickers with a particular tag.

    Args:
        tag: The tag to search for.

    Returns:
        A constructed URL for a particular tag.

    """
    return TAGS_BASE / f"{tag}/"


def chain(instrument_id: str) -> URL:
    """Build the query for a particular options chain.

    Args:
        instrument_id: The instrument in question.

    Returns:
        A constructed URL for the particular options chain search of the form
        ``/options/chains/?equity_instrument_ids=<id>``.

    Note:
        The previous implementation appended ``/ "/"`` to force a trailing
        slash. yarl rejects that construct with ``ValueError: Appending path
        '/' starting from slash is forbidden`` (issue #77). ``OPTIONS_CHAIN_BASE``
        already ends with ``/``, so the redundant append is dropped; the
        query parameter attaches cleanly via ``with_query``.
    """
    return OPTIONS_CHAIN_BASE.with_query(equity_instrument_ids=f"{instrument_id}")


def options(chain_id: str, dates: str, option_type: str) -> URL:
    """Build options search endpoint.

    # TODO: this really isn't best practice.

    Args:
        chain_id: The id for a particular options chain.
        dates: The range of dates to procure # TODO: document the format of the dates
        option_type: The type of the option # TODO: document the types
    """
    return OPTIONS_INSTRUMENTS_BASE.with_query(
        chain_id=f"{chain_id}",
        expiration_dates=f"{dates}",
        state="active",
        tradability="tradable",
        type=f"{option_type}",
    )


def market_data(option_id: Optional[str] = None) -> URL:
    """Build market data endpoint.

    Args:
        option_id: the id of the option. When omitted, the base market-data URL
            is returned.

    Returns:
        A constructed URL for market data for a particular ``option_id``, or
        :data:`MARKET_DATA_BASE` when no id is supplied.

    Note:
        Previously decorated ``@property`` (see commit history), which made
        this module-level function a non-callable ``property`` object; every
        call site raised ``TypeError``. The branches were also inverted,
        producing ``.../marketdata/None/`` when called with no argument. Both
        issues are fixed here.
    """
    if option_id is None:
        return MARKET_DATA_BASE
    else:
        return MARKET_DATA_BASE / f"{option_id}/"


def market_data_quotes(options_instruments) -> URL:
    """Build a batched market-data quotes URL.

    Args:
        options_instruments: An iterable of option instrument ids to fetch
            quotes for.

    Returns:
        A URL of the form ``/marketdata/quotes/?instruments=<id1>,<id2>,...``.

    Note:
        The previous implementation had no ``return`` statement and used
        invalid yarl path concatenation (``URL / "quotes/?instruments=" / ...``),
        so callers got ``None`` back.
    """
    return (MARKET_DATA_BASE / "quotes/").with_query(
        instruments=",".join(options_instruments)
    )


# ---------------------------------------------------------------------------
# Backward-compatibility aliases for the ``build_*`` helper names dropped in
# commit ``1cdb2ac`` (Nov 7 2024, "Harish's tweaks"). Issue #185.
#
# Each old name is kept as a thin wrapper that emits a ``DeprecationWarning``
# and forwards to the new name. This mirrors the ``instrument_URL`` →
# ``instrument_url`` shim pattern (issue #80) and the
# ``_raise_for_quote_http_error`` alias in ``pyrh/robinhood.py:196``.
#
# NOTE: wrappers are used (not bare-name aliases) so the deprecation warning
# fires on every call — a bare ``build_challenge = challenge`` would forward
# correctly but silently, defeating the migration signal the issue asks for.
# ---------------------------------------------------------------------------


def _make_build_alias(old_name: str, new_fn: Callable[..., URL]) -> Callable[..., URL]:
    """Return a wrapper that warns about the ``build_*`` rename and delegates."""

    @wraps(new_fn)
    def _alias(*args, **kwargs):
        warnings.warn(
            f"{old_name!r} is deprecated; use {new_fn.__name__!r} instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return new_fn(*args, **kwargs)

    _alias.__name__ = old_name
    _alias.__qualname__ = old_name
    _alias.__doc__ = (
        f"DEPRECATED alias for :func:`{new_fn.__name__}`. "
        f"Use :func:`{new_fn.__name__}` directly — this alias will be "
        f"removed in a future release."
    )
    return _alias


build_challenge = _make_build_alias("build_challenge", challenge)
build_ach = _make_build_alias("build_ach", ach)
build_orders = _make_build_alias("build_orders", orders)
build_news = _make_build_alias("build_news", news)
build_fundamentals = _make_build_alias("build_fundamentals", fundamentals)
build_tags = _make_build_alias("build_tags", tags)
build_chain = _make_build_alias("build_chain", chain)
build_options = _make_build_alias("build_options", options)
build_market_data = _make_build_alias("build_market_data", market_data)
