# coding=utf-8
"""Tests for ``pyrh.util`` package surface.

Specifically pins two regressions:

1. ``__all__`` listed ``JSON_ENCODING`` unquoted — so the string export
   contract actually listed the *value* ``"application/json"`` rather than
   the *name* ``"JSON_ENCODING"``. That makes
   ``from pyrh.util import *`` import nothing named ``JSON_ENCODING``,
   even though the constant is reachable via attribute access.
2. ``from pyrh import RobinhoodSchema`` — sanity check that the top-level
   export still resolves, after the renamings elsewhere in the package.
"""


def test_pyrh_util_all_lists_json_encoding_name():
    """``__all__`` must list the NAME ``"JSON_ENCODING"``, not its value.

    The earlier version was ``["headers", "robinhood_headers", JSON_ENCODING]``
    — the third entry was the *value* of the constant, not its name. That
    silently removes ``JSON_ENCODING`` from ``from pyrh.util import *``.
    """
    from pyrh import util

    assert "JSON_ENCODING" in util.__all__, (
        f"pyrh.util.__all__ must list the NAME 'JSON_ENCODING', "
        f"got {util.__all__!r}"
    )


def test_pyrh_util_star_import_exposes_json_encoding():
    """``from pyrh.util import *`` must make ``JSON_ENCODING`` available."""
    ns: dict = {}
    exec("from pyrh.util import *", ns)
    assert "JSON_ENCODING" in ns
    assert ns["JSON_ENCODING"] == "application/json"


def test_pyrh_robinhood_schema_import_works():
    """``from pyrh import RobinhoodSchema`` must resolve.

    ``pyrh/__init__.py`` exports ``RobinhoodSchema``; verify it's actually
    defined and importable from the top-level package.
    """
    from pyrh import RobinhoodSchema

    assert RobinhoodSchema is not None
