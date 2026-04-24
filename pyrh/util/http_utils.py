# coding=utf-8
"""HTTP defaults used when constructing pyrh sessions.

Issue #187 — ``headers`` and ``robinhood_headers`` are exposed as
``MappingProxyType`` read-only views so downstream callers cannot silently
mutate what looks like module-level constants.

Why read-only matters:

- ``robinhood_headers`` is read exactly once at import time by
  ``pyrh/models/sessionmanager.py`` via ``MappingProxyType(dict(
  robinhood_headers))``, so the ``HEADERS``-style leak-across-instances
  risk (issue #76) is low today. A future refactor that re-reads
  ``robinhood_headers`` on each call would silently re-open the leak —
  freezing the producer closes that door in advance.
- ``headers`` has no internal readers in pyrh at all. Any downstream
  caller who thinks ``pyrh.util.headers["X-Custom"] = "..."`` configures
  the library is silently wrong; freezing turns that silent wrongness
  into an explicit ``TypeError``.

Backwards-compatibility: read-side usage (``headers["User-Agent"]``,
``dict(robinhood_headers)``, iteration, ``len``, ``in``) is unchanged.
Only mutation (``x[k] = ...``, ``del x[k]``, ``x.update(...)`` etc.)
now raises ``TypeError``.
"""
from types import MappingProxyType

JSON_ENCODING = "application/json"

_headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/50.0.2661.102 Safari/537.36"
}

_robinhood_headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Robinhood-Api-Version": "1.431.4",
    "Connection": "keep-alive",
    "Content-Type": JSON_ENCODING,
    "Origin": "https://robinhood.com",
    "Referer": "https://robinhood.com",
    "Priority": "u=1, i",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}

# Public read-only views. Module-level name preserved so
# ``from pyrh.util import headers`` / ``robinhood_headers`` keeps working.
headers = MappingProxyType(_headers)
robinhood_headers = MappingProxyType(_robinhood_headers)
