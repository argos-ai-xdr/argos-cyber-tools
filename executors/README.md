# executors/

| Módulo | Herramienta | Estado |
| --- | --- | --- |
| [`kubernetes.py`](kubernetes.py) | `isolate_kubernetes_workload` | Real: `FakeClusterState` simula el efecto en memoria (sin clúster real, ARG-003); idempotencia real vía `IdempotencyStore` |
| [`scale_to_zero.py`](scale_to_zero.py) | `scale_to_zero` | Real, mismo patrón con `FakeReplicaState` |
| [`cilium.py`](cilium.py) | — | Interfaz para el cliente Cilium real; `kubernetes.py` ya cubre la simulación mientras tanto |
| [`evidence_verifier.py`](evidence_verifier.py) | — | `verify_artifact_integrity` es real (hash SHA-256); el cliente remoto hacia `evidence_writer` es interfaz pendiente (ARG-023) |

Ningún executor de aquí se invoca sin pasar por `mcp_gateway.Gateway.authorize` primero — eso es responsabilidad del llamador (Shuffle, `shuffle/playbooks/`), no de este módulo.
