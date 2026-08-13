# Política autoritativa para isolate_kubernetes_workload (ADR-005, ADR-011).
# argos-contracts-scenarios/scenarios/ARGOS-CYB-01/policies/ contiene una
# copia DESACTUALIZADA (usa target_allowlist a nivel de namespace,
# "namespace/argos-cyber-range") — este repositorio es el dueño de la
# política real y usa granularidad de recurso (deployment concreto), más
# restrictiva: una allowlist de namespace autorizaría implícitamente
# CUALQUIER deployment de ese namespace, no solo el activo del escenario.
# Ver argos-validation (evaluators/tool_calls) donde se documentó por
# primera vez esta inconsistencia entre repos — pendiente actualizar la
# copia de argos-contracts-scenarios para que coincida con esta.
package argos.cyber_tools.isolate_kubernetes_workload

import future.keywords.if

default decision := {"result": "DENY", "reason": "no matching rule"}

target_allowlist := {"deployment/gseg-simulado"}

decision := {"result": "ALLOW_DRY_RUN", "reason": "dry-run siempre permitido dentro del target allowlist"} if {
	input.action == "dry-run"
	input.target in target_allowlist
}

decision := {"result": "APPROVAL_REQUIRED", "reason": "execute requiere aprobación humana vinculada al action_id"} if {
	input.action == "execute"
	input.target in target_allowlist
	input.tool == "isolate_kubernetes_workload"
}

decision := {"result": "DENY", "reason": sprintf("target %v fuera de allowlist", [input.target])} if {
	not input.target in target_allowlist
}
