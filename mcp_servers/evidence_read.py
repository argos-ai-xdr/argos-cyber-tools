"""Servidor MCP de solo lectura hacia el evidence store — consulta de
EvidenceManifest, nunca escritura (esa es exclusiva de argos-core/services/
evidence_writer, ADR-006). Reutiliza executors.evidence_verifier para
comprobar integridad antes de exponer un artefacto.
"""
from __future__ import annotations

from typing import Protocol

from executors.evidence_verifier import RemoteEvidenceClient, verify_artifact_integrity


class EvidenceReadServer(Protocol):
    def get_manifest(self, *, run_id: str) -> dict: ...


class NotConfiguredEvidenceReadServer:
    def __init__(self, base_url: str):
        self._client = RemoteEvidenceClient(base_url)

    def get_manifest(self, *, run_id: str) -> dict:
        raise NotImplementedError(
            f"Lectura de EvidenceManifest para run_id={run_id!r} no "
            "implementada (ARG-023); ver executors/evidence_verifier.py."
        )


__all__ = ["EvidenceReadServer", "NotConfiguredEvidenceReadServer", "verify_artifact_integrity"]
