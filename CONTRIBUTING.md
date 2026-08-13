# Contribuir a argos-cyber-tools

1. Toda historia debe existir como issue `ARG-###` (ver `argos-control/project/backlog/backlog.yaml`). Primeras historias: ARG-011 (exposición y grafo), ARG-012 (privilegio excesivo), ARG-013 (attack path controlado), ARG-020 (policy gate y aprobación), ARG-021 (Shuffle y rollback).
2. Rama de trabajo: `feat/ARG-###-descripcion-corta`, `fix/...`.
3. Pull request obligatorio contra `main`. Sin push directo, force-push ni borrado de `main`. **Este repositorio no admite excepciones a esa regla.**
4. Toda herramienta nueva en `tool_catalog/definitions/` debe:
   - validar contra `tool_catalog/schemas/tool-definition.schema.json`;
   - declarar `risk_level`, `mode`, `required_scope`, `approval_required`, `idempotent`, `timeout_seconds`, `target_allowlist_required`, `rollback_supported`, `evidence_required` explícitamente — nunca con un valor por defecto implícito;
   - tener una estrategia en `rollback/` si `rollback_supported: true`;
   - tener un test en `tests/idempotency/` si `idempotent: true`.
5. Ningún ejecutor en `executors/` se invoca sin pasar por `mcp_gateway` y `policies/opa/` primero — ni siquiera en tests de integración locales.
6. Ninguna aprobación se acepta sin `approval_id` válido, no caducado, con `plan_hash` que coincida exactamente con la acción propuesta (anti-replay).
7. `make validate` y `make test` deben pasar; los tests de `tests/adversarial/` y `tests/authorization/` no se marcan `xfail` para "arreglar después" — si fallan, bloquean el PR.
