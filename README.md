# argos-cyber-tools

Capa de herramientas, políticas, sandbox y ejecución controlada. **Máxima criticidad de seguridad del proyecto** `argos-ai-xdr`: es el único lugar donde una decisión puede convertirse en una acción real sobre el entorno.

Parte de la organización [`argos-ai-xdr`](https://github.com/argos-ai-xdr). Arquitectura autoritativa y ADR en [`argos-control`](https://github.com/argos-ai-xdr/argos-control). Contratos y fixtures en [`argos-contracts-scenarios`](https://github.com/argos-ai-xdr/argos-contracts-scenarios).

## Separación obligatoria

```
read-only → dry-run → approval → execute → verify → rollback
```

Ninguna fase se salta. El LLM (`argos-core/services/recommendation`) nunca llama a un ejecutor directamente: siempre pasa por `mcp_gateway` → `policies` (OPA) → aprobación humana → `executors`.

## Contenido

| Carpeta | Contenido | Lógica |
| --- | --- | --- |
| `mcp_gateway/` | Punto de entrada único: valida audience, scope, allowlist, timeout; nunca reenvía el token del llamante | Real |
| `mcp_servers/` | Servidores de solo lectura (assets, vulnerabilities, cti, kubernetes-read, network-read, evidence-read) | Interfaz + real donde no requiere red |
| `tool_catalog/` | Definición firmable de cada herramienta (`schemas/`, `definitions/`, `risk-levels/`, `signatures/`) | Real |
| `policies/` | OPA (`opa/`), aprobación con TTL/anti-replay (`approval/`), allowlists (`target-allowlists/`), egress (`egress/`) | Real |
| `executors/` | Ejecutores idempotentes (`kubernetes`, `cilium`, `scale_to_zero`, `evidence_verifier`) | Real donde no requiere clúster |
| `rollback/` | Estrategia de reversión y verificación por herramienta | Real |
| `sandbox/` | Perfiles seccomp/AppArmor/red para el aislamiento de ejecución | Config real |
| `shuffle/` | Playbooks SOAR exportables (dry-run→approval→execute→verify→rollback) | Config real |
| `tests/` | `contract/`, `authorization/`, `anti-replay/`, `idempotency/`, `rollback/`, `adversarial/` | Real |

## Controles obligatorios (ver `argos-control/adr/ADR-003-mcp-security.md`)

mTLS/OIDC, audience exacta, scope por herramienta, sin token passthrough, target allowlist, timeout, egress deny, `approval_id`, `plan_hash`, TTL, anti-replay, idempotency key, verificación posterior, rollback, kill switch, segregación entre ejecutor y aprobador.

## Definition of Done

* El LLM no llama directamente a ejecutores.
* Ninguna acción crítica funciona sin aprobación.
* Las modificaciones invalidan el `plan_hash`.
* La aprobación caduca.
* El replay queda bloqueado.
* Toda acción es idempotente o se declara expresamente lo contrario.
* El rollback se prueba, no solo se documenta.
* El resultado produce `ActionResult` válido.

## Reglas comunes de la organización

Rama `main` protegida, PR obligatorio, `CODEOWNERS` reforzado en este repositorio (ver más abajo), sin push directo/force-push. Ver `docs/development.md`.
