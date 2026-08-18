"""R0-01, §11-13 (Zero Execute Proof + Bypass Analysis)."""
from __future__ import annotations

import datetime
import pathlib
import re

from executors.increase_monitoring import IncreaseMonitoringExecutor
from executors.kubernetes import KubernetesExecutor
from executors.scale_to_zero import ScaleToZeroExecutor
from mcp_gateway import Gateway, ToolCallRequest
from mcp_gateway.controlled_execution import execute_with_authorization
from policies.approval import compute_plan_hash, compute_signature_ref


def _safety_envelope(*, tool_name: str, target: str, action: str = "execute") -> dict:
    now = datetime.datetime.now(datetime.UTC)
    return {
        "envelope_id": "safenv-ce-1",
        "incident_ref": "inc-ce-1",
        "target_set": [target],
        "allowed_actions": [action],
        "forbidden_actions": [],
        "required_runbook": f"runbooks/{tool_name}.md",
        "rollback_ref": f"rollback/{tool_name}",
        "valid_until": (now + datetime.timedelta(minutes=15)).isoformat(),
        "envelope_hash": "sha256:" + "a" * 64,
        "signature": "sha256:" + "b" * 64,
    }


def _verification_result(envelope: dict, *, tool_name: str, target: str, state: str = "VERIFIED") -> dict:
    return {"state": state, "envelope_hash": envelope["envelope_hash"], "tool_name": tool_name, "target": target}


def _approval(*, plan_hash: str) -> dict:
    now = datetime.datetime.now(datetime.UTC)
    return {
        "approval_id": "appr-ce-1", "approver_id": "soc-1", "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref("appr-ce-1", plan_hash),
    }


class _Spy:
    """Espía real (no un mock que finja) -- cuenta invocaciones reales y
    devuelve un ActionResult mínimo plausible si llegara a ser llamado."""

    def __init__(self) -> None:
        self.call_count = 0
        self.calls: list[dict] = []

    def __call__(self, **kwargs: object) -> dict:
        self.call_count += 1
        self.calls.append(kwargs)
        return {"id": "act-spy-1", "status": "success"}


# ---------------------------------------------------------------------------
# §12: Zero Execute Proof -- denegado ⇒ executor_call_count == 0.
# ---------------------------------------------------------------------------


def test_denied_authorization_never_invokes_executor_missing_safety_chain():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
    )
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway, request, executor_call=spy, run_id="r1", idempotency_key="k1", action_id="a1",
    )
    assert outcome.authorized is False
    assert spy.call_count == 0


def test_denied_authorization_never_invokes_executor_verifier_rejected():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    envelope = _safety_envelope(tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", state="REJECTED")
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        safety_envelope=envelope, verification_result=verification,
    )
    spy = _Spy()
    outcome = execute_with_authorization(gateway, request, executor_call=spy, run_id="r1", idempotency_key="k1", action_id="a1")
    assert outcome.authorized is False
    assert spy.call_count == 0


def test_denied_authorization_never_invokes_executor_missing_approval():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    envelope = _safety_envelope(tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        safety_envelope=envelope, verification_result=verification,
    )
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway, request, executor_call=spy, run_id="r1", idempotency_key="k1", action_id="a1",
        current_plan_hash="sha256:" + "0" * 64,
    )
    assert outcome.authorized is False
    assert spy.call_count == 0


def test_authorized_execution_invokes_executor_exactly_once_with_derived_dry_run():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    plan_hash = compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")
    envelope = _safety_envelope(tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        approval=_approval(plan_hash=plan_hash), safety_envelope=envelope, verification_result=verification,
    )
    spy = _Spy()
    outcome = execute_with_authorization(
        gateway, request, executor_call=spy, run_id="r1", idempotency_key="k1", action_id="a1", current_plan_hash=plan_hash,
    )
    assert outcome.authorized is True
    assert spy.call_count == 1
    assert spy.calls[0]["dry_run"] is False
    assert spy.calls[0]["target"] == "deployment/gseg-simulado"


def test_dry_run_execution_invokes_executor_with_dry_run_true():
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="dry-run",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
    )
    spy = _Spy()
    outcome = execute_with_authorization(gateway, request, executor_call=spy, run_id="r1", idempotency_key="k1", action_id="a1")
    assert outcome.authorized is True
    assert spy.calls[0]["dry_run"] is True


# ---------------------------------------------------------------------------
# §11: las tres acciones ejecutables reales del catálogo, con executors
# REALES (no espías) -- prueba que el estado real cambia cuando se
# autoriza y NO cambia cuando se deniega.
# ---------------------------------------------------------------------------


def test_real_kubernetes_executor_state_changes_only_when_authorized(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    plan_hash = compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")
    envelope = _safety_envelope(tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado")
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        approval=_approval(plan_hash=plan_hash), safety_envelope=envelope, verification_result=verification,
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.isolate_workload,
        run_id="r-real-1", idempotency_key="k-real-1", action_id="a-real-1", current_plan_hash=plan_hash,
    )
    assert outcome.authorized is True
    assert executor.cluster.is_isolated("deployment/gseg-simulado")


def test_real_kubernetes_executor_state_untouched_when_denied(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    request = ToolCallRequest(
        tool_name="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        # Sin safety_envelope/verification_result/approval -- denegado.
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.isolate_workload,
        run_id="r-real-2", idempotency_key="k-real-2", action_id="a-real-2",
    )
    assert outcome.authorized is False
    assert not executor.cluster.is_isolated("deployment/gseg-simulado")


def test_real_scale_to_zero_executor_state_changes_only_when_authorized(contracts_path):
    executor = ScaleToZeroExecutor(contracts_path)
    executor.state.replicas["deployment/gseg-simulado"] = (3, 3)
    gateway = Gateway(target_allowlists={"scale_to_zero": {"deployment/gseg-simulado"}})
    plan_hash = compute_plan_hash(tool="scale_to_zero", target="deployment/gseg-simulado", action="execute")
    envelope = _safety_envelope(tool_name="scale_to_zero", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="scale_to_zero", target="deployment/gseg-simulado")
    request = ToolCallRequest(
        tool_name="scale_to_zero", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        approval=_approval(plan_hash=plan_hash), safety_envelope=envelope, verification_result=verification,
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.scale_to_zero,
        run_id="r-real-3", idempotency_key="k-real-3", action_id="a-real-3", current_plan_hash=plan_hash,
    )
    assert outcome.authorized is True
    assert executor.state.current_replicas("deployment/gseg-simulado") == 0


def test_real_scale_to_zero_executor_state_untouched_when_verifier_inconclusive(contracts_path):
    executor = ScaleToZeroExecutor(contracts_path)
    executor.state.replicas["deployment/gseg-simulado"] = (3, 3)
    gateway = Gateway(target_allowlists={"scale_to_zero": {"deployment/gseg-simulado"}})
    envelope = _safety_envelope(tool_name="scale_to_zero", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="scale_to_zero", target="deployment/gseg-simulado", state="INCONCLUSIVE")
    request = ToolCallRequest(
        tool_name="scale_to_zero", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.execute"}),
        safety_envelope=envelope, verification_result=verification,
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.scale_to_zero,
        run_id="r-real-4", idempotency_key="k-real-4", action_id="a-real-4",
    )
    assert outcome.authorized is False
    assert executor.state.replicas["deployment/gseg-simulado"] == (3, 3)


def test_real_increase_monitoring_executor_state_changes_only_when_authorized(contracts_path):
    executor = IncreaseMonitoringExecutor(contracts_path)
    gateway = Gateway()
    envelope = _safety_envelope(tool_name="increase_monitoring", target="deployment/gseg-simulado")
    verification = _verification_result(envelope, tool_name="increase_monitoring", target="deployment/gseg-simulado")
    request = ToolCallRequest(
        tool_name="increase_monitoring", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.monitor"}),
        safety_envelope=envelope, verification_result=verification,
        # approval_required=false para este tool -- se autoriza sin Approval.
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.increase_monitoring,
        run_id="r-real-5", idempotency_key="k-real-5", action_id="a-real-5",
    )
    assert outcome.authorized is True
    assert executor.state.current_level("deployment/gseg-simulado") == "verbose"


def test_real_increase_monitoring_executor_state_untouched_when_denied(contracts_path):
    executor = IncreaseMonitoringExecutor(contracts_path)
    gateway = Gateway()
    request = ToolCallRequest(
        tool_name="increase_monitoring", target="deployment/gseg-simulado", action="execute",
        subject="langgraph", caller_token="t", granted_scopes=frozenset({"cyber.response.monitor"}),
        # Sin safety_envelope/verification_result -- denegado pese a approval_required=false.
    )
    outcome = execute_with_authorization(
        gateway, request, executor_call=executor.increase_monitoring,
        run_id="r-real-6", idempotency_key="k-real-6", action_id="a-real-6",
    )
    assert outcome.authorized is False
    assert executor.state.current_level("deployment/gseg-simulado") == "normal"


# ---------------------------------------------------------------------------
# §13: Bypass Analysis -- ningún código de producción (fuera de tests/ y
# del propio controlled_execution.py) invoca los métodos de ejecución
# real de los tres executors.
# ---------------------------------------------------------------------------

#: Requiere un '.' inmediatamente antes (llamada real tipo
#: `objeto.metodo(`) -- evita falsos positivos como
#: `rollback_scale_to_zero(`/`rollback_increase_monitoring(`, que son
#: nombres de función DISTINTOS que solo comparten un sufijo de texto.
_FORWARD_EXECUTION_PATTERNS = (
    re.compile(r"\.isolate_workload\("),
    re.compile(r"\.scale_to_zero\("),
    re.compile(r"\.increase_monitoring\("),
)
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_ALLOWED_CALLERS = {
    _REPO_ROOT / "mcp_gateway" / "controlled_execution.py",
    # Los propios executors invocan, dentro de su implementación, un
    # método del MISMO nombre en su FakeXState interno (p. ej.
    # self.state.scale_to_zero(target) dentro de
    # ScaleToZeroExecutor.scale_to_zero) -- es la mutación de estado que
    # el método envuelve, no un bypass del límite de autorización.
    _REPO_ROOT / "executors" / "scale_to_zero.py",
    _REPO_ROOT / "executors" / "increase_monitoring.py",
}


def test_no_production_code_calls_executors_directly_outside_the_boundary():
    """Prueba estructural real (no solo una afirmación en un docstring):
    recorre el árbol de fuentes del repositorio (excluyendo tests/) y
    falla si aparece una llamada `objeto.metodo(` a uno de los tres
    métodos de ejecución real fuera de `controlled_execution.py` -- el
    único límite arquitectónico permitido tras R0-01."""
    violations: list[str] = []
    for path in _REPO_ROOT.rglob("*.py"):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        if path in _ALLOWED_CALLERS:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in _FORWARD_EXECUTION_PATTERNS:
            if pattern.search(text):
                violations.append(f"{path.relative_to(_REPO_ROOT)}: llamada directa a {pattern.pattern!r} fuera del límite autorizado")
    assert violations == [], "\n".join(violations)
