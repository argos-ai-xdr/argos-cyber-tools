"""Servidor MCP de solo lectura hacia snapshots CTI (MISP/ATT&CK/KEV/EPSS
fijados, ADR-007). Interfaz real; lectura de un snapshot real pendiente de
ARG-016 — ver argos-core/connectors/misp/.
"""
from __future__ import annotations

from typing import Protocol


class CTIReadServer(Protocol):
    def lookup_ioc(self, *, ioc: str, snapshot_ref: str) -> dict | None: ...


class NotConfiguredCTIReadServer:
    def lookup_ioc(self, *, ioc: str, snapshot_ref: str) -> dict | None:
        raise NotImplementedError(
            f"Lectura de snapshot CTI ({snapshot_ref}) no implementada (ARG-016)."
        )
