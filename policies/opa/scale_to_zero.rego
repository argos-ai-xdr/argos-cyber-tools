# Misma regla que isolate_kubernetes_workload.rego (mismo risk_level high,
# ver tool_catalog/definitions/scale_to_zero.yaml): dry-run libre dentro de
# la allowlist, execute requiere aprobación, fuera de allowlist siempre DENY.
package argos.cyber_tools.scale_to_zero

import future.keywords.if

default decision := {"result": "DENY", "reason": "no matching rule"}

target_allowlist := {"deployment/gseg-simulado"}  # granularidad de recurso, ver isolate_kubernetes_workload.rego

decision := {"result": "ALLOW_DRY_RUN", "reason": "dry-run siempre permitido dentro del target allowlist"} if {
	input.action == "dry-run"
	input.target in target_allowlist
}

decision := {"result": "APPROVAL_REQUIRED", "reason": "execute requiere aprobación humana vinculada al action_id"} if {
	input.action == "execute"
	input.target in target_allowlist
	input.tool == "scale_to_zero"
}

decision := {"result": "DENY", "reason": sprintf("target %v fuera de allowlist", [input.target])} if {
	not input.target in target_allowlist
}
