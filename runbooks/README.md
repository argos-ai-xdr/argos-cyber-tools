# runbooks/

Runbooks reales por herramienta del `tool_catalog/`, siguiendo la plantilla
`argos-control/templates/runbook/runbook-template.md` (ARG-028, S8: "as-built,
runbooks"). Ningún campo se rellena con datos inventados — donde algo
todavía no existe (sign-off real de SOC/Cyber, simulación contra un cluster
real) el runbook lo dice explícitamente en vez de fingirlo.

| Tool | Estado | Simulaciones registradas |
| --- | --- | --- |
| [`isolate_kubernetes_workload.md`](isolate_kubernetes_workload.md) | BORRADOR | 2 (en memoria) |
| [`scale_to_zero.md`](scale_to_zero.md) | BORRADOR | 1 (en memoria) — falta una segunda |

Tools del catálogo SIN runbook todavía:

* `read_asset_inventory` / `read_vulnerability_findings` — `mode: [read-only]`, sin `approval_required` ni `rollback_supported` (ver `tool_catalog/definitions/`); un runbook de contención no les aplica igual (no cambian estado), pendiente de decidir si necesitan una variante reducida de la plantilla.
* `increase_monitoring` — deliberadamente `approval_required: false` (ver `argos-cyber-tools/graph/attack_path.py`, caso `GATE_BYPASSED` documentado y probado en `tests/graph/test_attack_path.py::test_tool_without_approval_requirement_is_reported_as_gate_bypassed`); formalizar su runbook exige antes decidir si ese bypass deliberado se mantiene o se revisa, no es un simple relleno de plantilla.

Ninguno de los runbooks de esta carpeta se ha simulado todavía contra un
cyber-range real desplegado — todas las simulaciones citadas corren contra
`FakeClusterState`/`FakeReplicaState` en memoria (mismo bloqueo que
ENV-QUAL-01: sin cluster OSC/Gardener real no hay "última simulación" en el
sentido que exige el documento maestro para aprobar S6).
