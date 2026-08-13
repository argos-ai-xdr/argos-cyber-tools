"""Verifica que un artefacto de evidencia referenciado en un ActionResult
coincide de verdad con lo que escribió argos-core/services/evidence_writer
antes de confiar en él para un rollback o una verificación posterior —
comparación de hash real, no una llamada de red simulada como si funcionara.
"""
from __future__ import annotations

import hashlib


def verify_artifact_integrity(content: bytes, expected_sha256: str) -> bool:
    return hashlib.sha256(content).hexdigest() == expected_sha256


class RemoteEvidenceClient:
    """Cliente real hacia evidence_writer (HTTP/gRPC) — no implementado
    todavía (ARG-023, integración end-to-end). verify_artifact_integrity
    de este módulo ya es real y no depende de este cliente."""

    def __init__(self, base_url: str):
        self._base_url = base_url

    def fetch_artifact(self, artifact_id: str) -> bytes:
        raise NotImplementedError(
            f"Cliente hacia evidence_writer ({self._base_url}) no implementado "
            f"(ARG-023); no se puede obtener el artefacto {artifact_id!r} todavía."
        )
