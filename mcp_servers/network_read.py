"""Servidor MCP de solo lectura hacia flows de red (Hubble) — usado por el
grafo de exposición y validación de blast radius (ARG-011/ARG-014). Interfaz
real; cliente contra Hubble relay pendiente de ARG-011 (ver también
argos-core/connectors/hubble/).
"""
from __future__ import annotations

from typing import Protocol


class NetworkReadServer(Protocol):
    def get_flows(self, *, namespace: str) -> list[dict]: ...


class NotConfiguredNetworkReadServer:
    def __init__(self, relay_endpoint: str):
        self._relay_endpoint = relay_endpoint

    def get_flows(self, *, namespace: str) -> list[dict]:
        raise NotImplementedError(
            f"Cliente hacia Hubble relay ({self._relay_endpoint}) no "
            "implementado (ARG-011)."
        )
