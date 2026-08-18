"""DurableApprovalStore: cierre de ARG-020 (ADR-068 CHAOS-16, CH-07
KNOWN_FAILING) -- anti-replay de `Approval` que SOBREVIVE a un reinicio
de proceso, no solo dentro de la vida de un único `Gateway`.

**Núcleo local, no elección de backend de producción**: SQLite demuestra
el contrato (semántica durable + consumo atómico) sin comprometerse
todavía a PostgreSQL/Redis/lo que sea la infraestructura real de ARGOS
-- decisión explícita del usuario ("no elegiría todavía la tecnología de
persistencia"). `DURABLE_APPROVAL_CORE=IMPLEMENTED_LOCALLY_AND_TESTED`,
`TARGET_APPROVAL_BACKEND=BLOCKED_EXTERNAL/NOT_SELECTED` (multi-réplica
real del gateway, no evaluado aquí).

**Consumo atómico real, no una promesa**: `INSERT` con `approval_id`
como `PRIMARY KEY` -- si dos llamadas concurrentes intentan consumir la
MISMA `Approval`, SQLite serializa los writers (journal mode por
defecto) y exactamente una `INSERT` tiene éxito; la otra recibe
`sqlite3.IntegrityError` por violación de unicidad, traducido aquí a
`ApprovalRejected` (replay). Nunca "las dos parecen tener éxito".

**Fail-closed ante el propio almacén, nunca fallback a memoria**: si
SQLite no responde (fichero bloqueado más allá de `busy_timeout`,
inaccesible, etc.), se lanza `ApprovalStorageUnavailable` -- subclase de
`ApprovalRejected`, así que `mcp_gateway.Gateway.authorize` ya la trata
como `DENY` sin necesitar código nuevo en el gateway. Jamás se degrada
a "aceptar de todos modos" ni a un almacén en memoria silencioso.
"""
from __future__ import annotations

import datetime
import pathlib
import sqlite3

from policies.approval import ApprovalRejected, _validate_approval_fields


class ApprovalStorageUnavailable(ApprovalRejected):
    """El almacén durable no respondió -- tratado como DENY por
    `mcp_gateway.Gateway` (es una `ApprovalRejected`), nunca como
    "seguir sin persistencia"."""


class DurableApprovalStore:
    """Satisface `policies.approval.ApprovalStoreProtocol` estructuralmente
    -- inyectable en `mcp_gateway.Gateway(approval_store=...)` exactamente
    igual que `ApprovalStore` (en memoria)."""

    def __init__(self, db_path: str | pathlib.Path, *, busy_timeout_ms: int = 2000) -> None:
        self._db_path = str(db_path)
        try:
            self._conn = sqlite3.connect(self._db_path, timeout=busy_timeout_ms / 1000, isolation_level=None)
            self._conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS consumed_approvals ("
                "  approval_id TEXT PRIMARY KEY,"
                "  consumed_at TEXT NOT NULL,"
                "  action_binding TEXT NOT NULL"
                ")"
            )
        except sqlite3.Error as exc:
            raise ApprovalStorageUnavailable(f"no se pudo inicializar el almacén durable en {self._db_path!r}: {exc}") from exc

    def validate_and_consume(
        self,
        approval: dict,
        *,
        current_plan_hash: str,
        requester_id: str,
        executor_id: str,
        now: datetime.datetime,
    ) -> None:
        approval_id = _validate_approval_fields(
            approval, current_plan_hash=current_plan_hash, requester_id=requester_id, executor_id=executor_id, now=now
        )

        try:
            self._conn.execute(
                "INSERT INTO consumed_approvals (approval_id, consumed_at, action_binding) VALUES (?, ?, ?)",
                (approval_id, now.isoformat(), current_plan_hash),
            )
        except sqlite3.IntegrityError as exc:
            raise ApprovalRejected(f"replay: approval_id {approval_id!r} ya fue consumida (durable)") from exc
        except sqlite3.Error as exc:
            raise ApprovalStorageUnavailable(f"almacén durable no disponible al consumir {approval_id!r}: {exc}") from exc

    def is_consumed(self, approval_id: str) -> bool:
        """Solo para tests/observabilidad -- el camino de autorización real
        nunca debe consultar esto por separado (TOCTOU); `validate_and_consume`
        ya es la única fuente de verdad atómica."""
        try:
            row = self._conn.execute(
                "SELECT 1 FROM consumed_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise ApprovalStorageUnavailable(f"almacén durable no disponible al consultar {approval_id!r}: {exc}") from exc
        return row is not None

    def close(self) -> None:
        self._conn.close()
