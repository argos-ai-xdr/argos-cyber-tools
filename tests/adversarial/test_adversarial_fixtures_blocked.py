"""F09 (documento maestro v0.5, 5.3): reutiliza los fixtures REALES de
argos-contracts-scenarios/fixtures/adversarial/ (no datos inventados aquí)
para comprobar que mcp_gateway bloquea lo que ese repositorio ya documentó
como "debe bloquearse". Mismo principio que argos-core/tests/replay/.
"""
from __future__ import annotations

import json

import yaml

from mcp_gateway import Gateway, ToolCallRequest
from tool_catalog import ToolNotFound


def _load_adversarial_case(contracts_path, case_id):
    manifest_path = contracts_path / "fixtures" / "adversarial" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    case = next(c for c in manifest["cases"] if c["id"] == case_id)
    fixture_path = contracts_path / "fixtures" / "adversarial" / case["fixture"]
    return case, json.loads(fixture_path.read_text(encoding="utf-8"))


def test_tool_poisoning_fixture_does_not_match_any_real_tool(contracts_path):
    """El fixture de tool-poisoning tiene tool='isolate_kubernetes_workload
    && curl ...' — no coincide con NINGÚN nombre real del catálogo, así que
    el gateway lo rechaza estructuralmente (ToolNotFound), sin necesitar
    lógica de detección de inyección de comandos."""
    _, fixture = _load_adversarial_case(contracts_path, "tool-poisoning")
    gateway = Gateway()

    request = ToolCallRequest(
        tool_name=fixture["tool"],
        target=fixture["target"],
        action=fixture["action"],
        subject=fixture["subject"],
        caller_token="t",
        granted_scopes=frozenset({"cyber.response.execute"}),
    )
    try:
        gateway.authorize(request)
        raised = False
    except ToolNotFound:
        raised = True
    assert raised, "el tool envenenado no debería coincidir con ningún nombre de catálogo real"


def test_out_of_allowlist_fixture_is_denied_consistently_with_expected_result(contracts_path):
    """El fixture out-of-range ya documenta result='DENY' como ground
    truth (F09); confirmamos que NUESTRO gateway llega a la misma
    conclusión de forma independiente."""
    _, fixture = _load_adversarial_case(contracts_path, "out-of-range")
    assert fixture["result"] == "DENY"  # ground truth del propio fixture

    gateway = Gateway(target_allowlists={"isolate_kubernetes_workload": {"deployment/gseg-simulado"}})
    request = ToolCallRequest(
        tool_name=fixture["tool"],
        target=fixture["target"],
        action=fixture["action"],
        subject=fixture["subject"],
        caller_token="t",
        granted_scopes=frozenset({"cyber.response.execute"}),
    )
    result = gateway.authorize(request)
    assert result.allowed is False


def test_prompt_injection_fixture_is_not_mechanically_verifiable_here():
    """Documenta honestamente el límite: verificar que un LLM ignora una
    instrucción embebida en un campo de texto (fixtures/adversarial/
    prompt-injection/) requiere el sistema real corriendo (modes/real),
    igual que se documentó en argos-validation/suites/adversarial/
    suite.yaml. No hay nada que este repositorio pueda afirmar por sí solo
    sobre ese caso todavía."""
    assert True
