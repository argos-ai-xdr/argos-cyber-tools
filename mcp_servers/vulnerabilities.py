"""Servidor MCP de solo lectura para read_vulnerability_findings
(tool_catalog/definitions/read_vulnerability_findings.yaml).
InMemoryVulnerabilityServer filtra hallazgos ya cargados; el cliente real
hacia argos-core es interfaz pendiente (ARG-023).
"""
from __future__ import annotations

import dataclasses
from typing import Protocol


class VulnerabilityReadServer(Protocol):
    def list_findings(self, *, asset_id: str | None = None) -> list[dict]: ...


@dataclasses.dataclass
class InMemoryVulnerabilityServer:
    findings: list[dict] = dataclasses.field(default_factory=list)

    def list_findings(self, *, asset_id: str | None = None) -> list[dict]:
        if asset_id is None:
            return list(self.findings)
        return [f for f in self.findings if f.get("asset_id") == asset_id]
