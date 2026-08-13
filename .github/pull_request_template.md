## Historia

Enlaza la historia `ARG-###` (obligatorio): closes ARG-

## Qué cambia y por qué

## Checklist de seguridad (obligatorio en este repositorio)

- [ ] `make validate` y `make test` pasan localmente, incluidos `tests/authorization/` y `tests/adversarial/`.
- [ ] Si el PR añade una herramienta, cumple el checklist completo de `CONTRIBUTING.md` punto 4.
- [ ] Ningún `executor` se invoca sin pasar por `mcp_gateway` y `policies/opa/`.
- [ ] Ninguna `Approval` reutilizada, caducada o con `plan_hash` desajustado pasa la validación.
- [ ] Revisión de `qa-security-observer` solicitada si el cambio toca `mcp_gateway/`, `policies/`, `executors/` o `rollback/`.

## Evidencia / cómo se validó
