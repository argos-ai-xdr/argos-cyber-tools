# policies/

| Carpeta | Contenido | Lógica |
| --- | --- | --- |
| [`opa/`](opa/) | Rego autoritativo por herramienta | Real (Rego); sin servidor OPA desplegado todavía |
| [`approval/`](approval/) | TTL, anti-replay, segregación de funciones, `plan_hash` | **Real y probado** (Python) |
| [`target-allowlists/`](target-allowlists/) | Misma allowlist que `opa/`, en datos | Real |
| [`egress/`](egress/) | Qué puede alcanzar `mcp_gateway`/`executors` | Real (datos) |

`policies/approval/` es el control de seguridad más importante de este repositorio: valida que una `Approval` no esté caducada, reutilizada, o para una acción distinta de la que dice aprobar (`plan_hash`), y que quien aprueba no sea quien solicita ni quien ejecuta. Ver `../SECURITY.md`.
