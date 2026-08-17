from __future__ import annotations

import datetime

import pytest

from mcp_gateway import Gateway, RateLimiter, ToolCallRequest
from policies.approval import compute_plan_hash, compute_signature_ref
from tool_catalog import RateLimit, ToolDefinition, ToolNotFound


def _gateway():
    return Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})


def _tool(name: str, *, side_effect_class: str, calls_per_minute: int = 60, **overrides: object) -> ToolDefinition:
    base: dict[str, object] = {
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


def test_execute_without_approval_is_denied():
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="execute",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
        ),
        current_plan_hash="sha256:x",
    )
    assert result.allowed is False
    assert "Approval" in result.reason


def test_execute_with_valid_approval_is_allowed():
    plan_hash = compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")
    now = datetime.datetime.now(datetime.UTC)
    approval = {
        "approval_id": "appr-gw-1",
        "approver_id": "soc-1",
        "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref("appr-gw-1", plan_hash),
    }
    result = _gateway().authorize(
        ToolCallRequest(
            tool_name="isolate_kubernetes_workload",
            target="deployment/gseg-simulado",
            action="execute",
            subject="langgraph",
            caller_token="t",
            granted_scopes=frozenset({"cyber.response.execute"}),
            approval=approval,
        ),
        current_plan_hash=plan_hash,
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
    isolate_kubernetes_workload (5/min, ADR-019) no interfiera con lo que
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
    """ADR-019: un tool puede declararse IRREVERSIBLE/DESTRUCTIVE en su
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
    no deben chocar con el chequeo de ADR-019 — si el resultado es DENY
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
