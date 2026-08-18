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

**R0-01 (reconciliación global A→L, 2026-08-17)**: hasta esta versión,
`authorize()` no exigía SafetyEnvelope ni VerificationResult para
`action="execute"` — la cadena Safety Kernel→Independent Verifier
(`argos-core`, ADR-054/055) era correcta y estaba probada de forma
AISLADA, pero nada en este gateway la consultaba. Esto NO es una
funcionalidad nueva: es el cierre de un defecto de integración de
seguridad real (`architecture/implementation-readiness.md` §5, R0-01,
`argos-control`). Reutiliza exactamente los contratos ya reales de
`argos-core` (`safety-envelope` v1) como hechos suministrados por el
llamante — mismo patrón de "caller-supplied facts" que
`SafetyCheckInput`/`VerificationCheckInput` en `argos-core`, ya que este
repositorio no puede importar `argos-core` (límite de repos).

**Decisión de diseño explícita sobre `envelope_hash`**: este gateway NO
recomputa el hash criptográfico del SafetyEnvelope byte a byte —
hacerlo exigiría reproducir el campo exacto de `safety_kernel.
_build_envelope_payload` (argos-core) sin poder importarlo, lo que
crearía un acoplamiento oculto y frágil (un cambio futuro en esa lista
de campos rompería esta verificación en silencio, sin ningún test
compartido que lo detecte). En su lugar, el gateway valida: (1) formato
de `envelope_hash`/`signature` (`sha256:` + 64 hex), (2) vigencia
(`valid_until`), (3) binding real target/acción/tool contra el
envelope, y (4) que el `VerificationResult` referencia el MISMO
`envelope_hash` que el `SafetyEnvelope` suministrado — mismo criterio
de "referencia sellada, no recalculada" que ya usa `independent_verifier`
con `mission_context_hash` (K.1). Documentado aquí para que no se lea
como un descuido.

**R0-01-RESIDUAL, cerrado 2026-08-18 (sonda adversarial del usuario, no
inspección estática)**: una sonda real (tests/adversarial/
test_r0_01_residual_incident_confusion.py) demostró EJECUTANDO el ataque
(executor_call_count == 1, no 0) que, antes de este cierre, una Approval
firmada bajo el contexto de un incidente A podía autorizar `execute` bajo
el SafetyEnvelope/VerificationResult de un incidente B distinto sobre el
mismo tool/target/action -- ni SafetyEnvelope (`incident_ref`) ni Approval
(`action_id`, real en el contrato pero no leído aquí) se cruzaban entre sí;
la identidad de "plan" comprobada era solo el triple (tool, target,
action). Cerrado vinculando `current_plan_hash` al `envelope_hash` del
SafetyEnvelope de la solicitud (`params={"safety_envelope_hash": ...}` --
usa el dict abierto que `compute_plan_hash` ya tenía, sin inventar ningún
campo nuevo en los contratos congelados). `envelope_hash` ya identifica de
forma criptográfica el contenido íntegro del envelope, `incident_ref`
incluido -- vincularse a él es más fuerte que vincularse a `incident_ref`
directamente. La sonda, tras el fix, prueba `executor_call_count == 0`
para la misma combinación.

Límite que SÍ permanece, documentado y no cerrado aquí (alcance de
ARG-023): el llamante de producción que compute `current_plan_hash` (hoy
ninguno existe -- `graph.attack_path` es el único constructor real de
`ToolCallRequest`, y es validación de seguridad, nunca ejecución) deberá
incluir `safety_envelope_hash` en `params` con esta misma fórmula;
`argos-smartops/api/approvals.compute_plan_hash` (que crea la Approval
real) todavía no lo hace porque `PolicyDecision` v1 no expone
`envelope_hash` -- haría falta ese hilo completo (Safety Kernel ->
PolicyDecision -> Approval) para que una Approval real, no solo de test,
pueda satisfacer este binding.
"""
from __future__ import annotations

import dataclasses
import datetime
import re
import uuid

from policies.approval import ApprovalRejected, ApprovalStore, compute_plan_hash
from policies.target_allowlists import load_target_allowlists
from tool_catalog import DENIED_IN_P0, ToolDefinition, ToolNotFound, load_catalog

#: Mismo patrón que el schema real (safety-envelope v1: `envelope_hash`/
#: `signature`), usado aquí solo para detectar un valor obviamente
#: fabricado o corrupto -- no sustituye una recomputación criptográfica.
_HASH_REF_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


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
    #: R0-01: SafetyEnvelope v1 real (argos-core/services/safety_kernel,
    #: contrato 11) y el resultado de Independent Verifier
    #: (argos-core/services/independent_verifier), suministrados por el
    #: llamante -- este gateway no los genera, solo los exige y valida
    #: para action="execute". Ambos None es el valor por defecto
    #: deliberadamente inseguro para no-execute (read-only/dry-run no
    #: causan side effects, ver docstring de Gateway.authorize).
    safety_envelope: dict | None = None
    verification_result: dict | None = None


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

        if request.action == "execute":
            safety_denial = _check_safety_chain(request, tool, now=effective_now)
            if safety_denial is not None:
                return AuthorizationResult(False, safety_denial)

        if request.action == "execute" and tool.approval_required:
            if request.approval is None:
                return AuthorizationResult(False, "execute requiere Approval y no se proporcionó ninguna")
            if current_plan_hash is None:
                return AuthorizationResult(False, "current_plan_hash es obligatorio para validar la Approval")
            # R0-01-RESIDUAL (2026-08-18, sonda adversarial del usuario):
            # request.safety_envelope ya es no-None y válido aquí -- pasó
            # _check_safety_chain arriba, que se ejecuta para TODO
            # action=execute, no solo los que requieren Approval. Sin este
            # binding, current_plan_hash solo dependía de (tool, target,
            # action): una Approval firmada para el SafetyEnvelope del
            # incidente A era indistinguible, para el gateway, de una
            # Approval válida para el SafetyEnvelope de un incidente B
            # distinto sobre el mismo tool/target/action -- confirmado
            # EJECUTANDO el ataque (executor_call_count == 1), no solo por
            # inspección (ver tests/adversarial/
            # test_r0_01_residual_incident_confusion.py). envelope_hash ya
            # identifica de forma criptográfica el contenido íntegro del
            # SafetyEnvelope (incident_ref incluido) -- vincular el plan_hash
            # a él cierra la sustitución sin inventar ningún campo nuevo en
            # los contratos congelados (`params` de compute_plan_hash ya era
            # un dict abierto).
            assert request.safety_envelope is not None  # garantizado por _check_safety_chain arriba
            expected_plan_hash = compute_plan_hash(
                tool=tool.name,
                target=request.target,
                action=request.action,
                params={"safety_envelope_hash": request.safety_envelope["envelope_hash"]},
            )
            if current_plan_hash != expected_plan_hash:
                return AuthorizationResult(
                    False,
                    "current_plan_hash no está vinculado al envelope_hash del SafetyEnvelope de esta "
                    "solicitud (R0-01-RESIDUAL: posible sustitución de contexto entre incidentes)",
                )
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


def _check_safety_chain(request: ToolCallRequest, tool: ToolDefinition, *, now: datetime.datetime) -> str | None:
    """R0-01: cadena de seguridad obligatoria para `action="execute"` --
    devuelve `None` si la cadena es válida, o el motivo de denegación
    (fail-closed real: cualquier ausencia/inconsistencia deniega, nunca
    se asume segura). No decide autorización por sí misma -- Approval
    sigue siendo la única autoridad (§8 R0-01): esta comprobación solo
    exige que la evaluación de seguridad/verificación exista y sea
    consistente ANTES de llegar al chequeo de Approval."""
    envelope = request.safety_envelope
    if envelope is None:
        return "SafetyEnvelope ausente: requerido para action=execute (R0-01)"

    envelope_hash = envelope.get("envelope_hash")
    if not isinstance(envelope_hash, str) or not _HASH_REF_PATTERN.match(envelope_hash):
        return "SafetyEnvelope con envelope_hash ausente o con formato inválido"

    valid_until = envelope.get("valid_until")
    if not isinstance(valid_until, str):
        return "SafetyEnvelope sin valid_until"
    try:
        if now > datetime.datetime.fromisoformat(valid_until):
            return f"SafetyEnvelope expirado: valid_until={valid_until!r} < now={now.isoformat()!r}"
    except ValueError:
        return f"SafetyEnvelope con valid_until ilegible: {valid_until!r}"

    if request.target not in (envelope.get("target_set") or []):
        return f"target {request.target!r} no está en target_set del SafetyEnvelope"

    if request.action not in (envelope.get("allowed_actions") or []):
        return f"acción {request.action!r} no está en allowed_actions del SafetyEnvelope"

    expected_runbook = f"runbooks/{tool.name}.md"
    if envelope.get("required_runbook") != expected_runbook:
        return f"SafetyEnvelope no está vinculado a {tool.name!r} (required_runbook={envelope.get('required_runbook')!r}, esperado {expected_runbook!r})"

    verification = request.verification_result
    if verification is None:
        return "VerificationResult ausente: requerido para action=execute (R0-01)"

    state = verification.get("state")
    if state != "VERIFIED":
        return f"VerificationResult.state={state!r} != VERIFIED (ZERO EXECUTE, ADR-055)"

    if verification.get("envelope_hash") != envelope_hash:
        return "VerificationResult no referencia el envelope_hash del SafetyEnvelope suministrado (posible sustitución/replay entre planes)"

    if verification.get("tool_name") != tool.name or verification.get("target") != request.target:
        return "VerificationResult no está vinculado al mismo tool/target de esta solicitud"

    return None


def _mint_ephemeral_credential() -> str:
    # TODO (ARG-020): sustituir por un SVID real emitido por SPIRE
    # (argos-platform/platform/spire/), con audience y TTL cortos.
    return f"ephemeral-{uuid.uuid4().hex}"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)
