# Desarrollo en argos-cyber-tools

## Requisitos

* Python >= 3.11.
* `argos-contracts-scenarios` clonado como hermano de este repositorio (o `ARGOS_CONTRACTS_PATH`):

```text
argos-ai-xdr/
├── argos-cyber-tools/          (este repositorio)
└── argos-contracts-scenarios/
```

## Comandos

```bash
make bootstrap   # pip install -e ".[dev]" + pre-commit install
make validate    # ruff + mypy + YAML/JSON
make test        # pytest (contract/authorization/anti-replay/idempotency/rollback/adversarial)
```

## Antes de tocar un executor o una policy

1. Leer `SECURITY.md` — este repositorio no admite atajos "para probar rápido".
2. Ningún test de `tests/authorization/` ni `tests/adversarial/` se saltea ni se marca `xfail`.
3. Si añades una herramienta nueva, sigue el checklist de `CONTRIBUTING.md` punto 4 completo — no una parte.

## Antes de abrir un PR

1. `make validate` y `make test` sin errores.
2. El PR enlaza una historia `ARG-###`.
3. Revisión de `qa-security-observer` en cualquier cambio bajo `mcp_gateway/`, `policies/`, `executors/` o `rollback/` (ver `CODEOWNERS`).
