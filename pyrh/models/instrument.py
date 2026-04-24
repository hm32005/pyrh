# coding=utf-8
"""Stock Instruments in Robinhood."""

from typing import Iterable, Optional, cast

from marshmallow import fields

from pyrh import urls
from pyrh.exceptions import PyrhValueError

from pyrh.models.base import (
    BaseModel,
    BasePaginator,
    BasePaginatorSchema,
    BaseSchema,
    base_paginator,
)
from pyrh.models.sessionmanager import SessionManager


# TODO: dream up a good way to not require session to `get_fundamentals` without a
# Singleton pattern since there could be multiple sessions in the future.
class Instrument(BaseModel):
    """A financial instrument."""

    def get_fundamentals(self):  # type: ignore
        """TODO."""  # noqa: DAR401
        raise NotImplementedError()

    def get_market(self):  # type: ignore
        """TODO."""  # noqa: DAR401
        raise NotImplementedError()

    def get_quote(self):  # type: ignore
        """TODO."""  # noqa: DAR401
        raise NotImplementedError()

    def get_splits(self):  # type: ignore
        """TODO."""  # noqa: DAR401
        raise NotImplementedError()


class InstrumentSchema(BaseSchema):
    """The Schema for Instrument objects."""

    __model__ = Instrument
    # symbol query returns a paginator but we only want the first
    __first__ = "results"

    bloomberg_unique = fields.Str()
    country = fields.Str()
    day_trade_ratio = fields.Float()
    default_collar_fraction = fields.Float()
    fractional_tradability = fields.Str()  # TODO: determine possible values
    fundamentals = fields.URL()
    id = fields.UUID()
    list_date = fields.NaiveDateTime(format="%Y-%m-%d", allow_none=True)
    maintenance_ratio = fields.Float()
    margin_initial_ratio = fields.Float()
    market = fields.URL()
    # This value can be null: http://www.finra.org/industry/tick-size-pilot-program
    min_tick_size = fields.Float(allow_none=True)
    name = fields.Str()
    quote = fields.URL()
    rhs_tradability = fields.Str()  # TODO: determine possible values
    simple_name = fields.Str(allow_none=True)
    splits = fields.URL()
    state = fields.Str()  # TODO: determine possible values
    symbol = fields.Str()
    tradability = fields.Str()
    tradable_chain_id = fields.Str(allow_none=True)  # TODO: determine possible values
    tradeable = fields.Boolean()  # looks like they"re mixing UK and US english
    type = fields.Str()  # TODO: determine possible values
    url = fields.URL()


class InstrumentPaginator(BasePaginator):
    """Thin wrapper around `self.results`, a list of `Instruments`."""

    pass


class InstrumentPaginatorSchema(BasePaginatorSchema):
    """Schema class for the InstrumentPaginator.

    The nested results are of types `Instrument`.

    """

    __model__ = InstrumentPaginator

    results = fields.List(fields.Nested(InstrumentSchema))


class InstrumentManager(SessionManager):
    """Group together methods that manipulate instruments.

    Examples:
        >>> im = InstrumentManager()
        >>> im.instruments()  # Get all instruments
        >>> im.instrument(symbol="TSLA")  # Get a particular instrument

    """

    def instruments(self, query: Optional[str] = None) -> Iterable[Instrument]:
        """Get a generator of instruments.

        Args:
            query: If the query argument is provided, the returned values will be
                restricted to instruments that match the query keyword (single word).
                When omitted, fetches the unfiltered ``/instruments/`` listing.

        Returns:
            A generator of Instruments.

        Note:
            Issue #182: the previous implementation had the branches inverted
            -- it returned ``INSTRUMENTS_BASE`` when a query *was* supplied
            (silently dropping the user's query) and called
            ``urls.instruments(query=None)`` when no query was supplied (which,
            after the #78 tightening, raises ``ValueError``). Both arms are
            now correct.

        """
        url = (
            urls.instruments(query=query)
            if query is not None
            else urls.INSTRUMENTS_BASE
        )
        return base_paginator(url, self, InstrumentPaginatorSchema())

    def instrument(
        self, symbol: Optional[str] = None, id_: Optional[str] = None
    ) -> Instrument:
        """Get a single instrument using a provided query parameter.

        Note:
            The input parameters are mutually exclusive. Additionally, if you query a
            hidden symbol it will return emtpy. The only way to view hidden symbols is
            to use the instruments endpoint.

        Args:
            symbol: A ticker symbol
            id_: A UUID that represents an instrument

        Returns:
            A single instance of an `Instrument`

        Raises:
            PyrhValueError: Neither of the input kwargs are passed in.

        """
        if any(opt is not None for opt in [symbol, id_]):
            return cast(
                Instrument,
                self.get(
                    urls.instruments(symbol=symbol, id_=id_), schema=InstrumentSchema()
                ),
            )
        else:
            raise PyrhValueError("No valid options were provided.")
