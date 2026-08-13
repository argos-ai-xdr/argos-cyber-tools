# increase_monitoring (risk_level medium, tool_catalog/definitions/
# increase_monitoring.yaml): approval_required=false — no modifica el
# workload, solo eleva verbosidad de telemetría. Sin allowlist de destino:
# se permite en cualquier target del propio dominio de observabilidad.
package argos.cyber_tools.increase_monitoring

import future.keywords.if

default decision := {"result": "ALLOW_DRY_RUN", "reason": "increase_monitoring no requiere aprobación"}

decision := {"result": "ALLOW_DRY_RUN", "reason": "acción de solo observabilidad, sin riesgo de contención"} if {
	input.action in {"dry-run", "execute"}
	input.tool == "increase_monitoring"
}
