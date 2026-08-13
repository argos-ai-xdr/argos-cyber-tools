"""mcp_gateway: único punto de entrada entre argos-core/recommendation y
executors/mcp_servers (ADR-003). Valida scope, target allowlist y modo antes
de dejar pasar una llamada; nunca reenvía la credencial del llamante a la
capa siguiente (anti token-passthrough) — emite una credencial efímera
propia por llamada en su lugar (hoy un id opaco; SPIFFE/SPIRE real
pendiente de ARG-020).
"""
from __future__ import annotations

import dataclasses
import datetime
import uuid

from policies.approval import ApprovalRejected, ApprovalStore
from tool_catalog import ToolDefinition, ToolNotFound, load_catalog


class TokenPassthroughError(Exception):
    """Nunca debería lanzarse en operación normal — existe para que un test
    de tests/authorization/ pueda demostrar estructuralmente que el token
    del llamante no cruza el gateway."""


@dataclasses.dataclass(frozen=True)
class ToolCallRequest:
    tool_name: str
    target: str
    action: str  # "read-only" | "dry-run" | "execute"
    subject: str
    caller_token: str
    granted_scopes: frozenset[str]
    approval: dict | None = None


@dataclasses.dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    downstream_credential: str | None = None


class Gateway:
    def __init__(
        self,
        *,
        catalog: dict[str, ToolDefinition] | None = None,
        target_allowlists: dict[str, set[str]] | None = None,
        approval_store: ApprovalStore | None = None,
    ):
        self._catalog = catalog if catalog is not None else load_catalog()
        self._target_allowlists = target_allowlists or {}
        self._approval_store = approval_store or ApprovalStore()

    def authorize(self, request: ToolCallRequest, *, current_plan_hash: str | None = None) -> AuthorizationResult:
        try:
            tool = self._catalog[request.tool_name]
        except KeyError:
            raise ToolNotFound(request.tool_name) from None

        if request.action not in tool.mode:
            return AuthorizationResult(False, f"acción '{request.action}' no soportada por '{tool.name}' (mode={tool.mode})")

        if tool.required_scope not in request.granted_scopes:
            return AuthorizationResult(False, f"scope '{tool.required_scope}' no concedido al llamante")

        if tool.target_allowlist_required:
            allowlist = self._target_allowlists.get(tool.name, set())
            if request.target not in allowlist:
                return AuthorizationResult(False, f"target '{request.target}' fuera de la allowlist de '{tool.name}'")

        if request.action == "execute" and tool.approval_required:
            if request.approval is None:
                return AuthorizationResult(False, "execute requiere Approval y no se proporcionó ninguna")
            if current_plan_hash is None:
                return AuthorizationResult(False, "current_plan_hash es obligatorio para validar la Approval")
            try:
                self._approval_store.validate_and_consume(
                    request.approval,
                    current_plan_hash=current_plan_hash,
                    requester_id=request.subject,
                    executor_id="mcp_gateway",
                    now=_now(),
                )
            except ApprovalRejected as exc:
                return AuthorizationResult(False, f"Approval rechazada: {exc}")

        # Nunca se propaga request.caller_token más allá de este punto.
        downstream_credential = _mint_ephemeral_credential()
        if downstream_credential == request.caller_token:
            raise TokenPassthroughError("la credencial efímera coincidió con el token del llamante")

        return AuthorizationResult(True, "autorizado", downstream_credential=downstream_credential)


def _mint_ephemeral_credential() -> str:
    # TODO (ARG-020): sustituir por un SVID real emitido por SPIRE
    # (argos-platform/platform/spire/), con audience y TTL cortos.
    return f"ephemeral-{uuid.uuid4().hex}"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)
