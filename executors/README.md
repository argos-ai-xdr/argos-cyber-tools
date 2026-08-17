# executors/

| Módulo | Herramienta | Estado |
| --- | --- | --- |
| [`kubernetes.py`](kubernetes.py) | `isolate_kubernetes_workload` | Real: `FakeClusterState` simula el efecto en memoria (sin clúster real, ARG-003); idempotencia real vía `IdempotencyStore` |
| [`scale_to_zero.py`](scale_to_zero.py) | `scale_to_zero` | Real, mismo patrón con `FakeReplicaState` |
| [`cilium.py`](cilium.py) | — | Interfaz para el cliente Cilium real; `kubernetes.py` ya cubre la simulación mientras tanto |
| [`evidence_verifier.py`](evidence_verifier.py) | — | `verify_artifact_integrity` es real (hash SHA-256); el cliente remoto hacia `evidence_writer` es interfaz pendiente (ARG-023) |
| [`increase_monitoring.py`](increase_monitoring.py) | `increase_monitoring` | ADR-022 (Fase I): Real, mismo patrón con `FakeMonitoringState` (nivel de verbosidad `normal`/`verbose` por target). Backend elegido: Wazuh (única fuente de telemetría con adapter real hoy) — sin agente Wazuh real desplegado (ARG-003), como el resto de executors |

Ningún executor de aquí se invoca sin pasar por `mcp_gateway.Gateway.authorize` primero — eso es responsabilidad del llamador (Shuffle, `shuffle/playbooks/`), no de este módulo.

`action_id` en un ActionResult es la referencia COMPARTIDA a la decisión que se ejecuta (el `decision_id` del PolicyDecision, vía la Approval) — la ejecución original, sus reintentos idempotentes y su rollback llevan el MISMO `action_id`. El identificador único de un ActionResult concreto es `id` (el campo del envelope), no `action_id`; `rollback/strategies.py` usa `id` para `rollback_ref` por esta razón (ver su docstring — bug real encontrado ahí).
