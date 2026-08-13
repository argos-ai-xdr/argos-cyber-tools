# risk-levels/

Qué implica cada `risk_level` del catálogo — reforzado por el schema (`../schemas/tool-definition.schema.json`) para `high`/`critical`, no solo documentado aquí.

| `risk_level` | `approval_required` | `target_allowlist_required` | Ejemplo |
| --- | --- | --- | --- |
| `low` | Puede ser `false` (solo lectura) | Puede ser `false` | `read_asset_inventory` |
| `medium` | Puede ser `false` si no modifica estado del workload | Puede ser `false` | `increase_monitoring` |
| `high` | **Siempre `true`** (forzado por schema) | **Siempre `true`** (forzado por schema) | `isolate_kubernetes_workload`, `scale_to_zero` |
| `critical` | **Siempre `true`** (forzado por schema) | **Siempre `true`** (forzado por schema) | Ninguna herramienta de este catálogo todavía — reservado para acciones irreversibles, que el MVP no permite (ADR-011) |

Ninguna herramienta `critical` está implementada en este bootstrap: el documento maestro v0.5 (5.2) prohíbe la eliminación irreversible en el escenario ARGOS-CYB-01, y ADR-011 limita el MVP a L3 (observar, recomendar, dry-run, aprobar+ejecutar reversible).
