"""Validación real de Approval (ADR-003, ADR-011; 6.2.1 del documento
maestro: "La aprobación incluye action_id, hash del plan, rol, motivo y
expires_at; cualquier modificación invalida la firma").

`compute_signature_ref` es un checksum de integridad (SHA-256), NO una firma
criptográfica real — sin KMS/clave privada del aprobador todavía (ARG-020),
no se puede probar de forma no falsificable *quién* aprobó, solo detectar si
`plan_hash` cambió después de aprobar. Documentado explícitamente para que
nadie lo confunda con una firma real en producción.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json


class ApprovalRejected(Exception):
    pass


def compute_plan_hash(*, tool: str, target: str, action: str, params: dict | None = None) -> str:
    canonical = json.dumps(
        {"tool": tool, "target": target, "action": action, "params": params or {}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_signature_ref(approval_id: str, plan_hash: str) -> str:
    return "sha256:" + hashlib.sha256(f"{approval_id}:{plan_hash}".encode()).hexdigest()


def _parse(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts)


@dataclasses.dataclass
class ApprovalStore:
    """Rastrea approval_id ya consumidas en memoria — anti-replay real
    dentro del proceso. En producción esto vive en un almacén compartido
    (p. ej. NATS KV o el propio OPA), no en memoria de un único proceso
    (ARG-020)."""

    _consumed: set[str] = dataclasses.field(default_factory=set)

    def validate_and_consume(
        self,
        approval: dict,
        *,
        current_plan_hash: str,
        requester_id: str,
        executor_id: str,
        now: datetime.datetime,
    ) -> None:
        approval_id = approval["approval_id"]

        if approval_id in self._consumed:
            raise ApprovalRejected(f"replay: approval_id {approval_id!r} ya fue consumida")

        approver_id = approval["approver_id"]
        if approver_id == requester_id:
            raise ApprovalRejected("segregación de funciones: approver_id == requester_id")
        if approver_id == executor_id:
            raise ApprovalRejected("segregación de funciones: approver_id == executor_id")

        if approval["decision"] != "APPROVE":
            raise ApprovalRejected(f"decision={approval['decision']!r}, no APPROVE")

        expires_at = _parse(approval["expires_at"])
        if now > expires_at:
            raise ApprovalRejected(f"TTL expirado: now={now.isoformat()} > expires_at={expires_at.isoformat()}")

        expected_signature = compute_signature_ref(approval_id, current_plan_hash)
        if approval["signature_ref"] != expected_signature:
            raise ApprovalRejected(
                "signature_ref no coincide con el plan_hash actual — la acción cambió "
                "después de aprobarse, o la aprobación es para otra acción"
            )

        # Solo se marca consumida si TODAS las validaciones anteriores pasaron.
        self._consumed.add(approval_id)
