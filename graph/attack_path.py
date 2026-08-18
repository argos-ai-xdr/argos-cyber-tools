"""ARG-013 / C-07.UC3 (Attack path validation & adversarial emulation):
valida un EscalationFinding (ARG-012) contra la capa de autorización real
de este repositorio — mcp_gateway + policies — en vez de simular una
explotación. No basta con que el RBAC conceda un permiso excesivo: la capa
de tool_catalog/policies debe seguir exigiendo aprobación humana para
cualquier `execute`, incluso si el subject tiene privilegio de sobra
(defensa en profundidad, ADR-011). MVP-CYBER-RANGE: nunca se ejecuta nada
real, solo se pregunta al Gateway qué haría — ver
policies/target_allowlists.py y mcp_gateway.Gateway.authorize.
"""
from __future__ import annotations

import dataclasses

from graph.escalation import EscalationFinding
from mcp_gateway import Gateway, ToolCallRequest, ToolNotFound


@dataclasses.dataclass(frozen=True)
class AttackPathResult:
    finding: EscalationFinding
    tool_name: str
    target: str
    decision: str  # "VALIDATED" | "OUT_OF_SCOPE" | "GATE_BYPASSED"
    reason: str


def validate_attack_path(
    finding: EscalationFinding,
    *,
    tool_name: str,
    target: str,
    subject_id: str,
    granted_scopes: frozenset[str],
    gateway: Gateway | None = None,
    safety_envelope: dict | None = None,
    verification_result: dict | None = None,
) -> AttackPathResult:
    """Comprueba si, PESE al permiso RBAC excesivo de `finding`, un intento
    real de `execute` sobre `tool_name`/`target` sigue exigiendo Approval.

    - OUT_OF_SCOPE: el gateway rechaza por scope, modo o allowlist antes de
      llegar a la comprobación de Approval/cadena de seguridad — el path
      no es explotable con el catálogo de herramientas actual (nada que
      emular ni bloquear).
    - GATE_BYPASSED: el gateway autorizó `execute` SIN exigir ninguna
      barrera real (Approval, o desde R0-01 también SafetyEnvelope/
      VerificationResult) — fallo real de defensa en profundidad; debe
      bloquear el gate G3 (AC05/AC09), no quedar como hallazgo
      informativo.
    - VALIDATED: el gateway exige Approval y/o la cadena de seguridad
      (SafetyEnvelope+VerificationResult, R0-01) — el RBAC es excesivo,
      pero al menos una capa de contención real sigue bloqueando el
      impacto. Confirma la ruta sin ejecutar nada real.
    """
    gw = gateway or Gateway()
    request = ToolCallRequest(
        tool_name=tool_name,
        target=target,
        action="execute",
        subject=subject_id,
        caller_token="attack-path-validation",  # nunca sale de este proceso
        granted_scopes=granted_scopes,
        approval=None,  # deliberado: sin aprobación, para comprobar el gate
        safety_envelope=safety_envelope,
        verification_result=verification_result,
    )
    try:
        result = gw.authorize(request, current_plan_hash=None)
    except ToolNotFound as exc:
        return AttackPathResult(
            finding=finding,
            tool_name=tool_name,
            target=target,
            decision="OUT_OF_SCOPE",
            reason=f"'{exc}' no existe en el catálogo actual",
        )

    if result.allowed:
        return AttackPathResult(
            finding=finding,
            tool_name=tool_name,
            target=target,
            decision="GATE_BYPASSED",
            reason="execute fue autorizado SIN Approval ni cadena de seguridad — fallo de defensa en profundidad",
        )
    # R0-01: una denegación por falta de SafetyEnvelope/VerificationResult
    # es una barrera real tan válida como una denegación por Approval --
    # ambas demuestran que el gate contiene el impacto pese al RBAC
    # excesivo. "SafetyEnvelope"/"VerificationResult" se comprueban antes
    # que "Approval" en el gateway real, así que da igual cuál de las dos
    # frases aparezca primero en el motivo.
    if any(marker in result.reason for marker in ("Approval", "SafetyEnvelope", "VerificationResult")):
        return AttackPathResult(finding=finding, tool_name=tool_name, target=target, decision="VALIDATED", reason=result.reason)
    return AttackPathResult(finding=finding, tool_name=tool_name, target=target, decision="OUT_OF_SCOPE", reason=result.reason)
