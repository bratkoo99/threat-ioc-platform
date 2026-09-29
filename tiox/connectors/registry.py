"""
Connector registry.

Name -> connector instance. Deliberately trivial: the platform's value is that
adding a source is one class plus one line here, so there is no plugin machinery
to learn and no dynamic import to debug.

Also owns SCHEMA_VERSION checking. When the canonical schema moves to 2.0, this is
the single place that decides whether a connector is still compatible, instead of
every consumer of an event having to guess.
"""

from __future__ import annotations

import logging
from typing import Any, Type

from tiox.connectors.base import Connector, ConnectorError
from tiox.schemas.event import SCHEMA_VERSION

log = logging.getLogger(__name__)

# Connectors understood by this platform version. A connector declaring a
# different major schema version is registered but flagged, not silently used.
SUPPORTED_MAJOR = SCHEMA_VERSION.split(".", 1)[0]

_REGISTRY: dict[str, Connector] = {}


def register(connector: Connector) -> Connector:
    if not isinstance(connector, Connector):
        raise ConnectorError(f"{connector!r} is not a Connector")
    name = connector.NAME
    if name in _REGISTRY:
        raise ConnectorError(f"connector {name!r} already registered")
    _REGISTRY[name] = connector
    log.info("registered connector %s (source schema v%s)", name, connector.SCHEMA_VER)
    return connector


def get(name: str) -> Connector:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ConnectorError(
            f"unknown connector {name!r}; registered: {sorted(_REGISTRY)}"
        ) from None


def names() -> list[str]:
    return sorted(_REGISTRY)


def all_connectors() -> list[Connector]:
    return [_REGISTRY[n] for n in sorted(_REGISTRY)]


def is_compatible(connector: Connector) -> tuple[bool, str]:
    """Major-version compatibility check between source and platform schema."""
    try:
        major = connector.SCHEMA_VER.split(".", 1)[0]
    except AttributeError:
        return False, "connector has no SCHEMA_VER"
    if not connector.SCHEMA_VER or not connector.SCHEMA_VER[0].isdigit():
        return True, "unversioned connector, cannot check"
    if major != SUPPORTED_MAJOR:
        return False, f"source schema v{connector.SCHEMA_VER} != platform v{SCHEMA_VERSION}"
    return True, "ok"


def describe_all() -> list[dict[str, Any]]:
    out = []
    for c in all_connectors():
        d = c.describe()
        d["compatible"], d["compat_note"] = is_compatible(c)
        out.append(d)
    return out


def _register_builtins() -> None:
    from tiox.connectors.agent import AgentConnector

    register(AgentConnector())


_register_builtins()
