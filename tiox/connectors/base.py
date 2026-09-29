"""
Connector interface.

A connector is the only thing that knows about a specific data source. Its single
job is to turn that source's native payloads into canonical `Event` objects. It
must not talk to storage, must not make decisions, and must not care what
downstream detection does with the event.

Why this is the extension point that defines the product: writing a new source
integration is a class, one method, and no other changes. That is the property
that makes the platform inspectable and hackable rather than a closed product.
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Iterator

from tiox.schemas.event import SCHEMA_VERSION, Event, SchemaError

log = logging.getLogger(__name__)


class ConnectorError(RuntimeError):
    """Raised when a connector cannot normalize a payload."""


class Connector(abc.ABC):
    """
    Base class for all data-source connectors.

    Subclasses must declare:
      NAME        stable identifier, stored as Event.source
      SCHEMA_VER  the source's own payload version, tracked for re-normalization
    """

    NAME: str = "abstract"
    SCHEMA_VER: str = "0"

    # ---------- required ----------

    @abc.abstractmethod
    def normalize(self, payload: dict[str, Any], context: dict[str, Any] | None = None) -> list[Event]:
        """
        Convert one native payload into zero or more canonical events.

        Returning an empty list is a valid answer: a well-formed payload that
        happens to contain nothing we care about should not be an error.
        Raise SchemaError only when the payload is genuinely unparseable.
        """
        raise NotImplementedError

    # ---------- optional ----------

    def healthcheck(self) -> tuple[bool, str]:
        """Cheap liveness probe. Default: always healthy."""
        return True, "ok"

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.NAME,
            "source_schema_version": self.SCHEMA_VER,
            "platform_schema_version": SCHEMA_VERSION,
            "type": type(self).__name__,
        }

    # ---------- helpers for subclasses ----------

    def _event(self, **kwargs: Any) -> Event:
        """
        Build an Event with this connector's NAME defaulted in.

        ATT&CK techniques are resolved here, from the rule id and optionally the
        malware family, rather than being set by each connector. Centralising it
        means a new connector gets technique tagging for free and cannot forget.
        """
        kwargs.setdefault("source", self.NAME)
        if "techniques" not in kwargs:
            from tiox.schemas.attack import techniques_for_event

            family = ""
            raw = kwargs.get("raw") or {}
            if isinstance(raw, dict):
                family = str(raw.get("family") or "")
            resolved = techniques_for_event(kwargs.get("rule_id") or "", family)
            if resolved:
                kwargs["techniques"] = resolved
        try:
            return Event(**kwargs)
        except SchemaError:
            raise
        except TypeError as exc:
            raise ConnectorError(f"{self.NAME}: bad event construction: {exc}") from exc

    def _safe_iter(self, items: Any) -> Iterator[Any]:
        """Iterate a payload collection, tolerating the single-item / None cases."""
        if items is None:
            return iter(())
        if isinstance(items, dict):
            return iter([items])
        if isinstance(items, list):
            return iter(items)
        return iter((items,))
