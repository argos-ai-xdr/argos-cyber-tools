# Política de seguridad — argos-cyber-tools

Ver la política transversal en `argos-control/SECURITY.md`. Este es el repositorio de mayor criticidad de `argos-ai-xdr`.

## Reglas duras (no negociables sin ADR nuevo)

* `mcp_gateway` nunca reenvía el token de autenticación del llamante a un `mcp_server` o `executor` (anti token-passthrough, ADR-003) — cada salto obtiene su propia identidad de workload (SPIRE, `argos-platform/platform/spire/`).
* Ningún `executor` se invoca sin una `PolicyDecision` previa con `result` en `ALLOW_DRY_RUN` o, para `execute`, una `Approval` válida (`policies/approval/`).
* Una `Approval` reutilizada, caducada o con `plan_hash` que no coincide con la acción actual se rechaza — sin excepción, sin log-only.
* Segregación de funciones: `Approval.approver_id` nunca puede coincidir con el `subject` que solicitó la acción ni con quien la ejecuta.
* Toda acción con `idempotent: true` en su definición de `tool_catalog/` debe poder reintentarse con la misma `idempotency_key` sin duplicar el efecto.
* `sandbox/` aplica seccomp/AppArmor a todo ejecutor — un ejecutor sin perfil de sandbox asignado no se despliega.

## Reporte

Reportar vulnerabilidades o hallazgos vía el issue template `risk.yaml` o `exception.yaml` de `argos-control`, notificando al rol `qa-security-observer`. Una vulnerabilidad en `mcp_gateway`, `policies/approval/` o `executors/` se trata como incidente, no como bug ordinario.
