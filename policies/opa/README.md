# opa/

Política Rego autoritativa por herramienta (ADR-005). `argos-contracts-scenarios/scenarios/ARGOS-CYB-01/policies/` tiene una copia de referencia para que `argos-validation` pueda reproducir el escenario sin depender de este repositorio — si divergen, **esta carpeta manda**.

| Archivo | Herramienta | Regla |
| --- | --- | --- |
| `isolate_kubernetes_workload.rego` | `isolate_kubernetes_workload` | ALLOW_DRY_RUN en allowlist; APPROVAL_REQUIRED en execute; DENY fuera de allowlist |
| `scale_to_zero.rego` | `scale_to_zero` | Misma regla |
| `increase_monitoring.rego` | `increase_monitoring` | Sin aprobación (risk_level medium, sin modificación de workload) |

No implementado en este bootstrap: servidor OPA real desplegado (`argos-platform`) evaluando estos `.rego`; `policies/approval` (Python) es lo que se prueba de verdad hoy — ver `../approval/`.
