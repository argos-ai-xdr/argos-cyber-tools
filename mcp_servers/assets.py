"""Servidor MCP de solo lectura para read_asset_inventory
(tool_catalog/definitions/read_asset_inventory.yaml). InMemoryAssetServer es
real: filtra una lista de AssetSnapshot ya cargada — el cliente real hacia
argos-core (API o NATS) es interfaz pendiente (ARG-023).
"""
from __future__ import annotations

import dataclasses
from typing import Protocol


class AssetReadServer(Protocol):
    def list_assets(self, *, namespace: str | None = None) -> list[dict]: ...


@dataclasses.dataclass
class InMemoryAssetServer:
    """No inventa datos: expone exactamente lo que se le cargó
    (`assets`), nunca genera un AssetSnapshot sintético para rellenar."""

    assets: list[dict] = dataclasses.field(default_factory=list)

    def list_assets(self, *, namespace: str | None = None) -> list[dict]:
        if namespace is None:
            return list(self.assets)
        return [a for a in self.assets if a.get("namespace") == namespace]
