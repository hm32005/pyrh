# coding=utf-8
"""Export pyrh sub classes.

Lazy module attributes (PEP 562): heavy submodules like ``pyrh.robinhood``
(which transitively imports ``marshmallow`` and ``pyrh.models`` — ~400
modules and TLS/CFNetwork init on macOS) are loaded only when actually
accessed via ``pyrh.Robinhood`` or ``pyrh.RobinhoodSchema``. This keeps
``import pyrh.credentials`` (and any other lightweight submodule access)
import-light, which matters for fork-safety on macOS where eager TLS
init in a parent process before ``fork()`` deadlocks the child at
``socket.getaddrinfo``.

Lightweight imports (``cache``, ``constants``) stay eager — they're
stdlib-only and don't transitively load ``requests``/``urllib3``/etc.

Public surface unchanged: ``from pyrh import Robinhood`` still works
because PEP 562 fires ``__getattr__`` for names not already present in
the module dict.
"""
import importlib
from typing import Any

from .cache import dump_session, load_session
from .constants import CLIENT_ID, EXPIRATION_TIME, TIMEOUT

__version__ = "2.1.2"
__all__ = [
    "__version__",
    "Robinhood",
    "RobinhoodSchema",
    "load_session",
    "dump_session",
    "exceptions",
    "CLIENT_ID",
    "EXPIRATION_TIME",
    "TIMEOUT",
]

# name -> (submodule path, attribute name on that submodule)
_LAZY_ATTRS: dict[str, tuple[str, str]] = {
    "Robinhood": ("pyrh.robinhood", "Robinhood"),
    "RobinhoodSchema": ("pyrh.robinhood", "RobinhoodSchema"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_ATTRS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    value = getattr(importlib.import_module(module_name), attr)
    globals()[name] = value  # cache so subsequent lookups skip the import_module call
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_ATTRS) | set(__all__))
