from __future__ import annotations

import datetime

import pytest

from mcp_gateway import Gateway, ToolCallRequest
from policies.approval import compute_plan_hash, compute_signature_ref
from tool_catalog import ToolNotFound


def _gateway():
    return Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})


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
    coincide con el token del llamante — ninguna casualidad de hash."""
    gw = _gateway()
    caller_token = "same-token-every-time"
    for _ in range(50):
        result = gw.authorize(
            ToolCallRequest(
                tool_name="isolate_kubernetes_workload",
                target="deployment/gseg-simulado",
                action="dry-run",
                subject="langgraph",
                caller_token=caller_token,
                granted_scopes=frozenset({"cyber.response.execute"}),
            )
        )
        assert result.downstream_credential != caller_token
