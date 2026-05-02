"""Regression tests for lazy ``Robinhood`` / ``RobinhoodSchema`` exposure.

Importing ``pyrh.credentials`` (or any leaf module) must not pull
``pyrh.robinhood`` / ``marshmallow`` / ``pyrh.models`` — that's the
contract these tests lock in. Without it, macOS Airflow workers that
``fork()`` after touching pyrh deadlock at ``socket.getaddrinfo`` because
``requests`` / ``urllib3`` initialise CFNetwork in the parent before the
fork. PEP 562 ``__getattr__`` in ``pyrh/__init__.py`` defers the
``Robinhood`` / ``RobinhoodSchema`` symbols until they are actually
accessed, and ``pyrh.cache`` mirrors that with function-local imports.
"""
import importlib
import subprocess
import sys

import pytest

_HEAVY_PREFIXES = ("pyrh.robinhood", "pyrh.models", "marshmallow")


def _fresh_subprocess(stmt: str) -> subprocess.CompletedProcess:
    """Run a Python statement in a fresh interpreter so sys.modules starts empty."""
    return subprocess.run(
        [sys.executable, "-c", stmt],
        check=True,
        capture_output=True,
        text=True,
    )


def test_import_pyrh_credentials_does_not_load_heavy_modules() -> None:
    stmt = (
        "import sys; "
        "import pyrh.credentials; "
        "heavy = sorted(m for m in sys.modules if m.startswith(("
        f"{_HEAVY_PREFIXES!r})));"
        "print('|'.join(heavy))"
    )
    result = _fresh_subprocess(stmt)
    heavy = [m for m in result.stdout.strip().split("|") if m]
    assert not heavy, (
        f"importing pyrh.credentials pulled heavy modules: {heavy}. "
        "This re-introduces the macOS fork-livelock that the lazy "
        "__init__.py + cache.py import-defer is designed to prevent."
    )


def test_import_pyrh_does_not_eagerly_load_robinhood() -> None:
    stmt = (
        "import sys; import pyrh; "
        "print('pyrh.robinhood loaded' if 'pyrh.robinhood' in sys.modules "
        "else 'pyrh.robinhood deferred')"
    )
    result = _fresh_subprocess(stmt)
    assert "deferred" in result.stdout, (
        f"`import pyrh` eagerly loaded pyrh.robinhood: {result.stdout!r}. "
        "Either __init__.py reverted to `from .robinhood import Robinhood` "
        "at module top, or one of the still-eager submodules (cache, "
        "constants, exceptions) re-introduced the import chain."
    )


def test_pyrh_robinhood_attribute_is_lazy_loadable() -> None:
    stmt = (
        "import sys; import pyrh; "
        "assert 'pyrh.robinhood' not in sys.modules; "
        "R = pyrh.Robinhood; "
        "assert 'pyrh.robinhood' in sys.modules; "
        "assert R.__name__ == 'Robinhood'; "
        "print('OK')"
    )
    result = _fresh_subprocess(stmt)
    assert result.stdout.strip() == "OK"


def test_from_pyrh_import_robinhood_still_works() -> None:
    stmt = (
        "from pyrh import Robinhood, RobinhoodSchema, dump_session, load_session; "
        "print(Robinhood.__name__, RobinhoodSchema.__name__)"
    )
    result = _fresh_subprocess(stmt)
    assert "Robinhood RobinhoodSchema" in result.stdout


def test_pyrh_unknown_attribute_raises_attribute_error() -> None:
    # Verify the __getattr__ shim still raises AttributeError for unknown names —
    # otherwise typos like `pyrh.Robinwood` would silently return None.
    import pyrh

    importlib.reload(pyrh)
    with pytest.raises(AttributeError, match="has no attribute 'NoSuchAttr'"):
        _ = pyrh.NoSuchAttr  # noqa: F841


def test_pyrh_robinhood_caches_after_first_lookup() -> None:
    stmt = (
        "import sys; import pyrh; "
        "R1 = pyrh.Robinhood; "
        "R2 = pyrh.Robinhood; "
        "assert R1 is R2, 'Robinhood attribute should be cached after first lookup'; "
        "assert 'Robinhood' in pyrh.__dict__, 'cache writes through to module __dict__'; "
        "print('OK')"
    )
    result = _fresh_subprocess(stmt)
    assert result.stdout.strip() == "OK"
