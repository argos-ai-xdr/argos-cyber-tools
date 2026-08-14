# graph/

Grafo RBAC + red construido a partir de manifiestos Kubernetes reales (`kind: Role|ClusterRole|RoleBinding|ClusterRoleBinding|Service|Ingress|NetworkPolicy`) — no contra un clúster real (sin `argos-platform` desplegado, ARG-003), pero la lógica de grafo es real y se prueba contra fixtures realistas del escenario ARGOS-CYB-01, mismo patrón que `executors/kubernetes.py` con `FakeClusterState`.

| Módulo | Herramienta | Estado |
| --- | --- | --- |
| [`__init__.py`](__init__.py) | Grafo base: parseo de manifiestos, `effective_rules(subject)` (resuelve RoleBinding/ClusterRoleBinding respetando el alcance de cada uno) | Real |
| [`exposure.py`](exposure.py) | ARG-011 / C-07.UC1: qué `Service` es alcanzable desde fuera (Ingress, NodePort, LoadBalancer) vs solo interno, contrastado contra `policies/target_allowlists.py` | Real |
| [`escalation.py`](escalation.py) | ARG-012 / C-07.UC2: recorre `effective_rules` de cada subject contra un catálogo real de primitivas de escalada RBAC (wildcard, bind/escalate/impersonate, `pods/exec`, lectura de `secrets`) y reconstruye la ruta ServiceAccount → RoleBinding/ClusterRole → permiso excesivo (F04) | Real |

No se define un contrato v1 nuevo para estos resultados: el documento maestro fija "10 contratos v1" como conjunto cerrado (`AssetSnapshot` … `SOCHandover`), y ninguno de ellos es "grafo de exposición/RBAC" — son artefactos de análisis interno, potencialmente evidencia vía `EvidenceManifest`, no un mensaje nuevo entre servicios.

`graph.attack_path` (ARG-013) y `graph.blast_radius` (ARG-014) operan sobre el mismo `ClusterGraph`.
