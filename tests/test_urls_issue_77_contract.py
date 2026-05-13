"""Contract tests for issue #77: urls.chain() must not raise ValueError.

These tests are written as an independent QA check — they assert the
externally-observable contract of ``urls.chain`` without reading the
coding-agent's accompanying unit tests. Each test documents one
observable behavior that the fix must satisfy:

    1. ``urls.chain`` returns a :class:`yarl.URL` (no ValueError raised).
    2. The URL's path ends with ``/options/chains/``.
    3. The URL's query string contains ``equity_instrument_ids=<id>``.
    4. ``urls.chain`` is callable with a realistic UUID-shaped id.

Regression reference: before the fix the implementation appended
``/ "/"`` after ``with_query(...)``, which yarl rejects with
``ValueError: Appending path '/' starting from slash is forbidden``,
so every call to ``chain()`` exploded before returning a URL.
"""

from yarl import URL

from pyrh import urls


def test_chain_returns_yarl_url_without_raising() -> None:
    """Test 1: urls.chain("abc-123") returns a yarl URL (no ValueError)."""
    result = urls.chain("abc-123")
    assert isinstance(result, URL)


def test_chain_path_ends_with_options_chains() -> None:
    """Test 2: Returned URL path ends with ``/options/chains/``."""
    result = urls.chain("abc-123")
    assert result.path.endswith("/options/chains/"), (
        f"expected path to end with '/options/chains/', got {result.path!r}"
    )


def test_chain_query_string_contains_equity_instrument_ids() -> None:
    """Test 3: Query string contains ``equity_instrument_ids=abc-123``."""
    result = urls.chain("abc-123")
    assert "equity_instrument_ids=abc-123" in str(result), (
        f"expected 'equity_instrument_ids=abc-123' in URL, got {result!s}"
    )


def test_chain_callable_with_uuid_shaped_string() -> None:
    """Test 4: ``urls.chain`` is callable with a real UUID-shaped string."""
    uuid_id = "450dfc6d-5510-4d40-abfb-f633b7d9be3e"
    result = urls.chain(uuid_id)
    assert isinstance(result, URL)
    assert f"equity_instrument_ids={uuid_id}" in str(result)
