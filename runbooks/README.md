# runbooks/

Runbooks reales por herramienta del `tool_catalog/`, siguiendo la plantilla
`argos-control/templates/runbook/runbook-template.md` (ARG-028, S8: "as-built,
runbooks"). Ningún campo se rellena con datos inventados — donde algo
todavía no existe (sign-off real de SOC/Cyber, simulación contra un cluster
real) el runbook lo dice explícitamente en vez de fingirlo.

| Tool | Estado | Simulaciones / tests |
| --- | --- | --- |
| [`isolate_kubernetes_workload.md`](isolate_kubernetes_workload.md) | BORRADOR | 2 (en memoria) |
| [`scale_to_zero.md`](scale_to_zero.md) | BORRADOR | 1 (en memoria) — falta una segunda |
| [`read_asset_inventory.md`](read_asset_inventory.md) | BORRADOR | Sin Approval (read-only); `tests/mcp_servers/test_read_servers.py`, añadido junto con el runbook — antes el código real no tenía ningún test directo |
| [`read_vulnerability_findings.md`](read_vulnerability_findings.md) | BORRADOR | Igual que arriba |

`read_asset_inventory`/`read_vulnerability_findings` adaptan la plantilla
estándar (pensada para `dry-run→approval→execute→verify→rollback`):
`mode: [read-only]`, sin `approval_required` ni `rollback_supported` —
sus runbooks lo explican en vez de rellenar esas secciones con "N/A" sin
más.

Tool del catálogo SIN runbook todavía:

* `increase_monitoring` — deliberadamente `approval_required: false` (ver `argos-cyber-tools/graph/attack_path.py`, caso `GATE_BYPASSED` documentado y probado en `tests/graph/test_attack_path.py::test_tool_without_approval_requirement_is_reported_as_gate_bypassed`); formalizar su runbook exige antes decidir si ese bypass deliberado se mantiene o se revisa — una decisión de política de seguridad real, no algo que deba resolverse unilateralmente al escribir la plantilla.

Ninguno de los runbooks de esta carpeta se ha simulado todavía contra un
cyber-range real desplegado — todas las simulaciones citadas corren contra
`FakeClusterState`/`FakeReplicaState` en memoria (mismo bloqueo que
ENV-QUAL-01: sin cluster OSC/Gardener real no hay "última simulación" en el
sentido que exige el documento maestro para aprobar S6).
