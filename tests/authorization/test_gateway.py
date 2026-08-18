from __future__ import annotations

import datetime
from typing import Any

import pytest

from mcp_gateway import Gateway, RateLimiter, ToolCallRequest
from policies.approval import compute_plan_hash, compute_signature_ref
from tool_catalog import RateLimit, ToolDefinition, ToolNotFound


def _gateway():
    return Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})


def _tool(name: str, *, side_effect_class: str, calls_per_minute: int = 60, **overrides: object) -> ToolDefinition:
    base: dict[str, Any] = {
        "name": name,
        "version": "1.0.0",
        "risk_level": "low",
        "mode": ("read-only", "dry-run", "execute"),
        "required_scope": "cyber.test",
        "approval_required": False,
        "idempotent": True,
        "timeout_seconds": 30,
        "target_allowlist_required": False,
        "rollback_supported": True,
        "evidence_required": False,
        "side_effect_class": side_effect_class,
        "rate_limit": RateLimit(calls_per_minute=calls_per_minute),
    }
    base.update(overrides)
    return ToolDefinition(**base)


def _request(tool_name: str, action: str = "dry-run") -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=tool_name,
        target="n/a",
        action=action,
        subject="x",
        caller_token="t",
        granted_scopes=frozenset({"cyber.test"}),
    )


def _safety_envelope(
    *,
    tool_name: str = "isolate_kubernetes_workload",
    target: str = "deployment/gseg-simulado",
    action: str = "execute",
    valid_until: datetime.datetime | None = None,
    envelope_hash: str = "sha256:" + "a" * 64,
) -> dict:
    """R0-01: fixture de un SafetyEnvelope v1 real, mínimo pero
    estructuralmente válido -- mismos campos que
    argos-core/services/safety_kernel._build_envelope_payload."""
    now = datetime.datetime.now(datetime.UTC)
    return {
        "envelope_id": "safenv-test-1",
        "incident_ref": "inc-test-1",
        "target_set": [target],
        "allowed_actions": [action],
        "forbidden_actions": [],
        "required_runbook": f"runbooks/{tool_name}.md",
        "rollback_ref": f"rollback/{tool_name}",
        "valid_until": (valid_until or (now + datetime.timedelta(minutes=15))).isoformat(),
        "envelope_hash": envelope_hash,
        "signature": "sha256:" + "b" * 64,
    }


def _verification_result(
    envelope: dict,
    *,
    tool_name: str = "isolate_kubernetes_workload",
    target: str = "deployment/gseg-simulado",
    state: str = "VERIFIED",
) -> dict:
    """R0-01: fixture del resultado de Independent Verifier -- referencia
    el envelope_hash del SafetyEnvelope suministrado, nunca uno propio."""
    return {"state": state, "envelope_hash": envelope["envelope_hash"], "tool_name": tool_name, "target": target}


def test_dry_run_with_correct_scope_and_target_is_allowed():
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="dry-run",
            subject="langgraph",
            caller_token="secret-caller-token",
            granted_scopes=frozenset({"cyber.response.execute"}),
        )
    )
    assert result.allowed is True
    assert result.downstream_credential != "secret-caller-token"


def test_missing_scope_is_denied():
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="dry-run",
            subject="x",
            caller_token="t",
            granted_scopes=frozenset(),
        )
    )
    assert result.allowed is False
    assert "scope" in result.reason


def test_target_outside_allowlist_is_denied():
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="namespace/production-payments",
            action="dry-run",
            subject="x",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
        )
    )
    assert result.allowed is False
    assert "allowlist" in result.reason


def _approval(*, plan_hash: str, approval_id: str = "appr-gw-1") -> dict:
    now = datetime.datetime.now(datetime.UTC)
    return {
        "approval_id": approval_id,
        "approver_id": "soc-1",
        "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref(approval_id, plan_hash),
    }


def test_execute_without_approval_is_denied():
    """Con una cadena de seguridad VÁLIDA pero sin Approval -- Approval
    sigue siendo obligatoria e independiente (§8 R0-01: Safety Kernel/
    Verifier nunca sustituyen la autorización humana)."""
    envelope = _safety_envelope()
    verification = _verification_result(envelope)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="execute",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope,
            verification_result=verification,
        ),
        current_plan_hash="sha256:x",
    )
    assert result.allowed is False
    assert "Approval" in result.reason


def test_execute_with_valid_approval_is_allowed():
    """Camino feliz completo tras R0-01: SafetyEnvelope válido +
    VerificationResult VERIFIED + Approval válida -> allowed."""
    plan_hash = compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")
    envelope = _safety_envelope()
    verification = _verification_result(envelope)
    approval = _approval(plan_hash=plan_hash)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="execute",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
            approval=approval,
            safety_envelope=envelope,
            verification_result=verification,
        ),
        current_plan_hash=plan_hash,
    )
    assert result.allowed is True


# ---------------------------------------------------------------------------
# R0-01: cadena de seguridad obligatoria para action=execute (Definition of
# Done §15/§16 -- argos-control/architecture/implementation-readiness.md §5).
# ---------------------------------------------------------------------------


def test_execute_with_valid_approval_but_without_safety_envelope_is_denied():
    """§9 R0-01, prueba de regresión OBLIGATORIA: una Approval históricamente
    válida (target_allowlist + Approval) YA NO basta por sí sola para
    autorizar una acción con side effects -- esto es lo que demuestra que
    R0-01 está realmente cerrado, no solo documentado."""
    plan_hash = compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")
    approval = _approval(plan_hash=plan_hash)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="execute",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
            approval=approval,
            # Deliberadamente SIN safety_envelope/verification_result.
        ),
        current_plan_hash=plan_hash,
    )
    assert result.allowed is False
    assert "SafetyEnvelope" in result.reason


def test_execute_with_invalid_envelope_hash_format_is_denied():
    envelope = _safety_envelope(envelope_hash="not-a-real-hash")
    verification = _verification_result(envelope)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "envelope_hash" in result.reason


def test_execute_with_expired_envelope_is_denied():
    now = datetime.datetime.now(datetime.UTC)
    envelope = _safety_envelope(valid_until=now - datetime.timedelta(minutes=1))
    verification = _verification_result(envelope)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
        now=now,
    )
    assert result.allowed is False
    assert "expirado" in result.reason


def test_execute_with_target_outside_envelope_is_denied():
    """El target de la solicitud no está en target_set del envelope --
    aunque esté en la allowlist del tool (dos comprobaciones distintas,
    ninguna sustituye a la otra)."""
    envelope = _safety_envelope(target="deployment/otro-workload")
    verification = _verification_result(envelope, target="deployment/otro-workload")
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "target_set" in result.reason


def test_execute_with_action_outside_envelope_is_denied():
    envelope = _safety_envelope(action="dry-run")  # el envelope solo autorizó dry-run
    verification = _verification_result(envelope)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "allowed_actions" in result.reason


def test_execute_with_envelope_bound_to_another_tool_is_denied():
    envelope = _safety_envelope(tool_name="scale_to_zero")  # required_runbook apunta a otro tool
    verification = _verification_result(envelope)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "vinculado" in result.reason


def test_execute_with_missing_verification_result_is_denied():
    envelope = _safety_envelope()
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope,
            # Deliberadamente sin verification_result.
        ),
    )
    assert result.allowed is False
    assert "VerificationResult" in result.reason


@pytest.mark.parametrize("state", ["INCONCLUSIVE", "REJECTED"])
def test_execute_with_non_verified_state_is_denied(state):
    """INCONCLUSIVE y REJECTED significan lo mismo para ejecución: ZERO
    EXECUTE (mismo literal que independent_verifier, ADR-055)."""
    envelope = _safety_envelope()
    verification = _verification_result(envelope, state=state)
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert state in result.reason


def test_execute_with_verification_result_missing_state_is_denied():
    """Un VerificationResult mal formado (sin `state`) nunca se trata
    como VERIFIED por defecto -- `None != "VERIFIED"` deniega igual."""
    envelope = _safety_envelope()
    verification = {"envelope_hash": envelope["envelope_hash"], "tool_name": "isolate_kubernetes_workload", "target": "deployment/gseg-simulado"}
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False


def test_execute_with_verification_result_referencing_another_envelope_hash_is_denied():
    """Sustitución/replay entre planes: el VerificationResult referencia
    un envelope_hash distinto al del SafetyEnvelope realmente
    suministrado en esta solicitud."""
    envelope = _safety_envelope()
    other_envelope = _safety_envelope(envelope_hash="sha256:" + "c" * 64)
    verification = _verification_result(other_envelope)  # referencia el hash del OTRO envelope
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "envelope_hash" in result.reason


def test_execute_with_verification_result_bound_to_another_target_is_denied():
    envelope = _safety_envelope()
    verification = _verification_result(envelope, target="deployment/otro-target")
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "vinculado" in result.reason


def test_execute_with_verification_result_bound_to_another_tool_is_denied():
    envelope = _safety_envelope()
    verification = _verification_result(envelope, tool_name="scale_to_zero")
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is False
    assert "vinculado" in result.reason


def test_execute_safety_chain_required_even_when_tool_does_not_require_approval():
    """increase_monitoring tiene approval_required=false en su
    ToolManifest real -- pero eso no exime la cadena de seguridad
    determinista (SafetyEnvelope+VERIFIED), solo la autorización humana."""
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="increase_monitoring", target="n/a", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.monitor"}),
            # Deliberadamente sin safety_envelope/verification_result.
        ),
    )
    assert result.allowed is False
    assert "SafetyEnvelope" in result.reason


def test_execute_with_full_valid_safety_chain_and_no_approval_required_is_allowed():
    """Contraparte positiva del test anterior: con la cadena de seguridad
    completa y válida, increase_monitoring (approval_required=false) SÍ
    se autoriza sin Approval -- la exigencia nueva es aditiva, no rompe
    el diseño ya ratificado de ese tool."""
    envelope = _safety_envelope(tool_name="increase_monitoring", target="n/a")
    verification = _verification_result(envelope, tool_name="increase_monitoring", target="n/a")
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="increase_monitoring", target="n/a", action="execute",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.monitor"}),
            safety_envelope=envelope, verification_result=verification,
        ),
    )
    assert result.allowed is True


def test_dry_run_never_requires_safety_envelope():
    """§10 R0-01: no se fuerza la cadena completa sobre dry-run/read-only
    -- solo action=execute causa side effects reales."""
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="dry-run",
            subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        ),
    )
    assert result.allowed is True


def test_unsupported_action_for_tool_is_denied():
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="read_asset_inventory",
            target="n/a",
            action="execute",  # read_asset_inventory solo soporta read-only
            subject="x",
            caller_token="t",
            granted_scopes=frozenset({"cyber.read.assets"}),
        )
    )
    assert result.allowed is False
    assert "no soportada" in result.reason


def test_unknown_tool_raises():
    with pytest.raises(ToolNotFound):
        _gateway().authorize(
            ToolCallRequest(
                tool_name="delete_everything",
                target="x",
                action="execute",
                subject="x",
                caller_token="t",
                granted_scopes=frozenset(),
            )
        )


def test_gateway_without_explicit_allowlist_loads_the_real_one_from_disk():
    """Regresión: Gateway() sin target_allowlists explícito caía a {}
    (denegar todo target-allowlisted), no porque el target realmente no
    estuviera permitido sino porque nada cargaba
    policies/target-allowlists/*.yaml — el mismo dato que policies/opa/
    ya documenta como el ground truth. Mismo patrón que catalog=None (que sí
    caía a load_catalog())."""
    gateway = Gateway()  # sin target_allowlists explícito
    result = gateway.authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",  # el target real de policies/target-allowlists/isolate_kubernetes_workload.yaml
            action="dry-run",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
        )
    )
    assert result.allowed is True


def test_downstream_credential_is_never_the_caller_token_across_many_calls():
    """Chequeo estructural: en 50 llamadas, la credencial descendente nunca
    coincide con el token del llamante — ninguna casualidad de hash.
    `now` avanza 2 minutos por llamada para que el rate_limit de
    isolate_kubernetes_workload (5/min, ADR-053) no interfiera con lo que
    este test realmente comprueba — si degradara a `allowed=False` por
    límite de tasa, `downstream_credential` sería None y la aserción
    pasaría por accidente sin haber probado nada."""
    gw = _gateway()
    caller_token = "same-token-every-time"
    now = datetime.datetime.now(datetime.UTC)
    for i in range(50):
        result = gw.authorize(
            ToolCallRequest(
                tool_name="isolate_kubernetes_workload",
                target="deployment/gseg-simulado",
                action="dry-run",
                subject="langgraph",
                caller_token=caller_token,
                granted_scopes=frozenset({"cyber.response.execute"}),
            ),
            now=now + datetime.timedelta(minutes=2 * i),
        )
        assert result.allowed is True
        assert result.downstream_credential != caller_token


@pytest.mark.parametrize("side_effect_class", ["IRREVERSIBLE", "DESTRUCTIVE"])
def test_irreversible_and_destructive_tools_are_always_denied_in_p0(side_effect_class):
    """ADR-053: un tool puede declararse IRREVERSIBLE/DESTRUCTIVE en su
    catálogo (el schema lo permite, son categorías válidas de
    ToolManifest v1) pero el gateway nunca lo autoriza en el P0 actual —
    ni con scope correcto, ni con approval, ni en modo read-only."""
    tool = _tool("dangerous_tool", side_effect_class=side_effect_class)
    gateway = Gateway(catalog={"dangerous_tool": tool}, target_allowlists={})

    result = gateway.authorize(_request("dangerous_tool", action="read-only"))

    assert result.allowed is False
    assert side_effect_class in result.reason
    assert "P0" in result.reason


@pytest.mark.parametrize("side_effect_class", ["READ_ONLY", "DRY_RUN", "REVERSIBLE_WRITE"])
def test_side_effect_classes_up_to_reversible_write_are_not_denied_by_this_rule(side_effect_class):
    """El reverso de la regla anterior: READ_ONLY/DRY_RUN/REVERSIBLE_WRITE
    no deben chocar con el chequeo de ADR-053 — si el resultado es DENY
    aquí, tiene que venir de otra regla (scope/allowlist/approval), nunca
    de side_effect_class."""
    tool = _tool("safe_tool", side_effect_class=side_effect_class)
    gateway = Gateway(catalog={"safe_tool": tool}, target_allowlists={})

    result = gateway.authorize(_request("safe_tool", action="read-only"))

    assert result.allowed is True


def test_rate_limit_denies_the_call_that_exceeds_calls_per_minute():
    tool = _tool("throttled_tool", side_effect_class="READ_ONLY", calls_per_minute=3)
    gateway = Gateway(catalog={"throttled_tool": tool}, target_allowlists={})
    now = datetime.datetime.now(datetime.UTC)

    for _ in range(3):
        result = gateway.authorize(_request("throttled_tool"), now=now)
        assert result.allowed is True

    fourth = gateway.authorize(_request("throttled_tool"), now=now)
    assert fourth.allowed is False
    assert "rate_limit" in fourth.reason


def test_rate_limit_counts_denied_attempts_too():
    """El límite de tasa debe acotar el VOLUMEN de intentos, no solo los
    autorizados — un llamante que hace spam de peticiones con scope
    incorrecto (siempre denegadas por otra razón) igualmente debe agotar
    su cupo, para que no sirva de vía de fuerza bruta ilimitada."""
    tool = _tool("throttled_tool", side_effect_class="READ_ONLY", calls_per_minute=2, required_scope="needs.this.scope")
    gateway = Gateway(catalog={"throttled_tool": tool}, target_allowlists={})
    now = datetime.datetime.now(datetime.UTC)

    bad_request = ToolCallRequest(
        tool_name="throttled_tool", target="n/a", action="read-only", subject="x", caller_token="t", granted_scopes=frozenset()
    )
    r1 = gateway.authorize(bad_request, now=now)
    r2 = gateway.authorize(bad_request, now=now)
    assert r1.allowed is False and "scope" in r1.reason
    assert r2.allowed is False and "scope" in r2.reason

    r3 = gateway.authorize(bad_request, now=now)
    assert r3.allowed is False
    assert "rate_limit" in r3.reason  # ya no llega a evaluar el scope: el cupo se agotó


def test_rate_limit_window_resets_after_a_minute():
    tool = _tool("throttled_tool", side_effect_class="READ_ONLY", calls_per_minute=1)
    gateway = Gateway(catalog={"throttled_tool": tool}, target_allowlists={})
    now = datetime.datetime.now(datetime.UTC)

    first = gateway.authorize(_request("throttled_tool"), now=now)
    denied = gateway.authorize(_request("throttled_tool"), now=now + datetime.timedelta(seconds=30))
    later = gateway.authorize(_request("throttled_tool"), now=now + datetime.timedelta(seconds=61))

    assert first.allowed is True
    assert denied.allowed is False
    assert later.allowed is True


def test_rate_limiter_can_be_injected_and_is_independent_per_gateway_instance():
    """Mismo patrón de inyección que approval_store: un RateLimiter externo
    permite compartir estado entre gateways (p. ej. en un test que simula
    dos réplicas) y confirma que, sin inyectar uno, cada Gateway() tiene
    el suyo propio (no hay estado global oculto)."""
    tool = _tool("throttled_tool", side_effect_class="READ_ONLY", calls_per_minute=1)
    now = datetime.datetime.now(datetime.UTC)

    shared = RateLimiter()
    gw1 = Gateway(catalog={"throttled_tool": tool}, target_allowlists={}, rate_limiter=shared)
    gw2 = Gateway(catalog={"throttled_tool": tool}, target_allowlists={}, rate_limiter=shared)
    assert gw1.authorize(_request("throttled_tool"), now=now).allowed is True
    assert gw2.authorize(_request("throttled_tool"), now=now).allowed is False  # comparte cupo con gw1

    fresh_gw = Gateway(catalog={"throttled_tool": tool}, target_allowlists={})
    assert fresh_gw.authorize(_request("throttled_tool"), now=now).allowed is True  # RateLimiter propio, sin inyectar
