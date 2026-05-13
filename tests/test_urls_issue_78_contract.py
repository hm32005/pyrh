"""Contract tests for pyrh issue #78.

``urls.instruments()`` used to silently ``return None`` when called without
any of ``symbol`` / ``query`` / ``id_``. Callers then passed that ``None`` to
``requests.get()``, which raised ``MissingSchema: Invalid URL 'None'`` — an
error far from the real bug.

These tests pin the post-fix contract:

1. No-kwargs call raises :class:`ValueError` (not silent ``None``).
2. The error message mentions at least one of the required kwarg names.
3. The happy paths for each of ``symbol``, ``query``, and ``id_`` still
   return a usable URL.

Written independently by the QA agent without reading the coding agent's
tests, per the review contract.
"""

from __future__ import annotations

import pytest
from yarl import URL

from pyrh import urls


class TestInstrumentsNoKwargsContract:
    """``instruments()`` with no kwargs must fail loudly."""

    def test_no_kwargs_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            urls.instruments()

    def test_error_message_mentions_a_kwarg_name(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            urls.instruments()
        msg = str(exc_info.value)
        assert any(
            name in msg for name in ("symbol", "query", "id_")
        ), f"ValueError message must mention at least one of symbol/query/id_, got: {msg!r}"


class TestInstrumentsHappyPathsStillWork:
    """The fix must not break any of the three valid call forms."""

    def test_symbol_returns_url(self) -> None:
        result = urls.instruments(symbol="AAPL")
        assert isinstance(result, URL)
        assert str(result)  # non-empty, stringifiable
        assert "AAPL" in str(result)

    def test_query_returns_url(self) -> None:
        result = urls.instruments(query="apple")
        assert isinstance(result, URL)
        assert str(result)
        assert "apple" in str(result)

    def test_id_returns_url(self) -> None:
        result = urls.instruments(id_="abc-123")
        assert isinstance(result, URL)
        assert str(result)
        assert "abc-123" in str(result)
