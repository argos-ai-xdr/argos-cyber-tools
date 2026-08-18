"""RBAC + red: grafo real construido a partir de manifiestos Kubernetes con
forma de API real (ServiceAccount referenciado por RoleBinding.subjects,
Role/ClusterRole, RoleBinding/ClusterRoleBinding, Service, Ingress,
NetworkPolicy) — no contra un clúster real (sin argos-platform desplegado,
ARG-003), pero la lógica de grafo es real y se prueba contra fixtures F04
reales, mismo patrón que executors/kubernetes.py con FakeClusterState.

ARG-011 (C-07.UC1): construir el grafo y detectar exposición (graph.exposure).
ARG-012 (C-07.UC2) y ARG-014 (C-07.UC4) operan sobre el mismo ClusterGraph
(graph.escalation, graph.blast_radius).

No se define un contrato v1 nuevo para el resultado: el documento maestro
fija "10 contratos v1" como conjunto cerrado (AssetSnapshot ... SOCHandover,
ver argos-contracts-scenarios/schemas/), y ninguno de ellos es "grafo de
exposición/RBAC" — los resultados de C-07 son artefactos de análisis interno
(potencialmente evidencia vía EvidenceManifest), no un mensaje nuevo entre
servicios.

El modelo de datos real (`ClusterGraph`, `build_graph`, etc.) vive en
`graph.model`, no aquí -- este `__init__.py` solo re-exporta la API
pública. Los submódulos (`escalation.py`, `blast_radius.py`,
`exposure.py`) importan de `graph.model` directamente, nunca de `graph`
(su propio paquete padre) -- ver `graph/model.py` para por qué.
"""
from __future__ import annotations

from graph.model import (
    ClusterGraph,
    IngressDef,
    InvalidManifest,
    NetworkPolicyDef,
    PolicyRule,
    RoleBindingDef,
    RoleDef,
    ServiceDef,
    Subject,
    build_graph,
)

__all__ = [
    "ClusterGraph",
    "IngressDef",
    "InvalidManifest",
    "NetworkPolicyDef",
    "PolicyRule",
    "RoleBindingDef",
    "RoleDef",
    "ServiceDef",
    "Subject",
    "build_graph",
]
