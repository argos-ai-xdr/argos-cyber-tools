"""Validación real de Approval (ADR-003, ADR-011; 6.2.1 del documento
maestro: "La aprobación incluye action_id, hash del plan, rol, motivo y
expires_at; cualquier modificación invalida la firma").

`compute_signature_ref` es un checksum de integridad (SHA-256), NO una firma
criptográfica real — sin KMS/clave privada del aprobador todavía (ARG-020),
no se puede probar de forma no falsificable *quién* aprobó, solo detectar si
`plan_hash` cambió después de aprobar. Documentado explícitamente para que
nadie lo confunda con una firma real en producción.

**Cierre de ARG-020/CH-07 (2026-08-18)**: `ApprovalStore` (en memoria) sigue
existiendo tal cual para tests unitarios rápidos, pero YA NO es la única
implementación -- `durable_store.DurableApprovalStore` (SQLite) satisface la
MISMA interfaz (`ApprovalStoreProtocol`) con semántica durable: el estado de
consumo sobrevive a un reinicio de proceso (`Gateway` puede inyectar
cualquiera de las dos, ver `mcp_gateway.Gateway.__init__`). La validación de
campos (segregación de funciones, TTL, `signature_ref`) se extrajo a
`_validate_approval_fields` para que AMBAS implementaciones compartan
exactamente la misma lógica -- solo el paso de "marcar consumida" difiere
(en memoria vs. `INSERT` atómico en SQLite).
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
from typing import Protocol


class ApprovalRejected(Exception):
    pass


class ApprovalStoreProtocol(Protocol):
    """Interfaz que `mcp_gateway.Gateway` exige de cualquier almacén de
    Approval, en memoria o durable -- estructural (Protocol), no
    herencia, para que `DurableApprovalStore` no tenga que fingir ser un
    `ApprovalStore` (dataclass en memoria) para satisfacer el tipo."""

    def validate_and_consume(
        self,
        approval: dict,
        *,
        current_plan_hash: str,
        requester_id: str,
        executor_id: str,
        now: datetime.datetime,
    ) -> None: ...


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


def _validate_approval_fields(
    approval: dict, *, current_plan_hash: str, requester_id: str, executor_id: str, now: datetime.datetime
) -> str:
    """Comprobaciones comunes a CUALQUIER implementación de almacén
    (segregación de funciones, decisión, TTL, firma) -- todo lo que NO
    depende de si el estado de consumo es en memoria o durable. Devuelve
    `approval_id` (ya validado como presente) para que el llamante solo
    tenga que resolver el paso de consumo. Lanza `ApprovalRejected` en la
    primera comprobación que falle -- nunca marca nada como consumido
    aquí."""
    approval_id = approval["approval_id"]

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

    return approval_id


@dataclasses.dataclass
class ApprovalStore:
    """Rastrea approval_id ya consumidas en memoria -- anti-replay real
    dentro de ESTE proceso únicamente. No sobrevive a un reinicio
    (confirmado ejecutando el reinicio de verdad, no solo citado:
    `argos-cyber-tools/tests/adversarial/
    test_chaos_16_gateway_restart_r0_01_regression.py`, ADR-068 CHAOS-16)
    -- para anti-replay que sí sobreviva, usar `durable_store.
    DurableApprovalStore`. Se mantiene para tests unitarios rápidos que
    no necesitan tocar disco."""

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

        approval_id = _validate_approval_fields(
            approval, current_plan_hash=current_plan_hash, requester_id=requester_id, executor_id=executor_id, now=now
        )

        # Solo se marca consumida si TODAS las validaciones anteriores pasaron.
        self._consumed.add(approval_id)
