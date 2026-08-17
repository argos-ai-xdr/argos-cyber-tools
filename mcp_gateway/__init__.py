"""mcp_gateway: único punto de entrada entre argos-core/recommendation y
executors/mcp_servers (ADR-003). Valida scope, target allowlist y modo antes
de dejar pasar una llamada; nunca reenvía la credencial del llamante a la
capa siguiente (anti token-passthrough) — emite una credencial efímera
propia por llamada en su lugar (hoy un id opaco; SPIFFE/SPIRE real
pendiente de ARG-020).

ADR-053 (SECURE TOOL LIFECYCLE) añade dos reglas más: ningún tool con
`side_effect_class` IRREVERSIBLE/DESTRUCTIVE puede autorizarse en el P0
actual (sin importar scope/target/approval — el catálogo puede declarar
uno, pero el gateway nunca lo deja pasar), y cada llamada cuenta contra el
`rate_limit` declarado por el propio tool (ventana deslizante de 60s).
"""
from __future__ import annotations

import dataclasses
import datetime
import uuid

from policies.approval import ApprovalRejected, ApprovalStore
from policies.target_allowlists import load_target_allowlists
from tool_catalog import DENIED_IN_P0, ToolDefinition, ToolNotFound, load_catalog


class TokenPassthroughError(Exception):
    """Nunca debería lanzarse en operación normal — existe para que un test
    de tests/authorization/ pueda demostrar estructuralmente que el token
    del llamante no cruza el gateway."""


@dataclasses.dataclass
class RateLimiter:
    """Ventana deslizante de 60s en memoria por `tool_name` (ADR-053). En
    producción esto vive en un almacén compartido entre réplicas del
    gateway (p. ej. NATS KV), no en memoria de un único proceso — mismo
    caveat ya documentado para ApprovalStore (ARG-020)."""

    _calls: dict[str, list[datetime.datetime]] = dataclasses.field(default_factory=dict)

    def check_and_record(self, tool_name: str, *, calls_per_minute: int, now: datetime.datetime) -> bool:
        """Devuelve False (y no cuenta la llamada) si ya se alcanzó el
        límite; devuelve True (y SÍ cuenta la llamada) en caso contrario.
        Cuenta todo intento, autorizado o no — el propósito de un rate
        limit es acotar el volumen de intentos, no solo de éxitos."""
        window_start = now - datetime.timedelta(minutes=1)
        history = [t for t in self._calls.get(tool_name, ()) if t > window_start]
        if len(history) >= calls_per_minute:
            self._calls[tool_name] = history
            return False
        history.append(now)
        self._calls[tool_name] = history
        return True


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
        rate_limiter: RateLimiter | None = None,
    ):
        self._catalog = catalog if catalog is not None else load_catalog()
        self._target_allowlists = target_allowlists if target_allowlists is not None else load_target_allowlists()
        self._approval_store = approval_store or ApprovalStore()
        self._rate_limiter = rate_limiter or RateLimiter()

    def authorize(
        self, request: ToolCallRequest, *, current_plan_hash: str | None = None, now: datetime.datetime | None = None
    ) -> AuthorizationResult:
        try:
            tool = self._catalog[request.tool_name]
        except KeyError:
            raise ToolNotFound(request.tool_name) from None

        if tool.side_effect_class in DENIED_IN_P0:
            return AuthorizationResult(
                False, f"side_effect_class '{tool.side_effect_class}' fuera de alcance del P0 (ADR-053, DENY incondicional)"
            )

        effective_now = now or _now()
        if not self._rate_limiter.check_and_record(
            tool.name, calls_per_minute=tool.rate_limit.calls_per_minute, now=effective_now
        ):
            return AuthorizationResult(False, f"rate_limit excedido para '{tool.name}' ({tool.rate_limit.calls_per_minute}/min)")

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
                    now=effective_now,
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
