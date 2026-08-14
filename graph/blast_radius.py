"""ARG-014 / C-07.UC4 (Blast radius assessment): dado un recurso
comprometido (Service + subject), calcula el conjunto afectado real por
dos rutas independientes:

  - Red: otros Service del mismo namespace, salvo que una NetworkPolicy
    default-deny (graph.is_default_deny) aísle el namespace — sin ella se
    asume movimiento lateral posible, no se descarta en silencio.
  - RBAC: otros subjects que comparten CUALQUIER RoleBinding/
    ClusterRoleBinding con el mismo Role/ClusterRole que el subject
    comprometido — si ese rol se revoca o contiene, les afecta a todos.

Produce una recomendación GO/NARROW/STOP de contención — no una
simulación de adversario general (ADR-011: dry-run/simulación acotada al
cyber-range, nunca predicción autónoma del atacante).
"""
from __future__ import annotations

import dataclasses

from graph import ClusterGraph, Subject


@dataclasses.dataclass(frozen=True)
class BlastRadiusAssessment:
    target_service: str  # "namespace/nombre"
    affected_services: tuple[str, ...]
    affected_subjects: tuple[str, ...]
    recommendation: str  # "GO" | "NARROW" | "STOP"
    reason: str


def _namespace_has_default_deny(graph: ClusterGraph, namespace: str) -> bool:
    return any(np.namespace == namespace and np.is_default_deny for np in graph.network_policies)


def _affected_services(graph: ClusterGraph, target_namespace: str, target_name: str) -> tuple[str, ...]:
    if _namespace_has_default_deny(graph, target_namespace):
        return ()
    others = [
        svc.qualified_name
        for (namespace, name), svc in graph.services.items()
        if namespace == target_namespace and name != target_name
    ]
    return tuple(sorted(others))


def _subject_label(subject: Subject) -> str:
    return f"{subject.namespace}/{subject.name}" if subject.namespace else subject.name


def _affected_subjects(graph: ClusterGraph, subject: Subject) -> tuple[str, ...]:
    roles_bound = {(rb.role_ref_kind, rb.role_ref_name) for rb in graph.role_bindings if subject in rb.subjects}
    others: set[str] = set()
    for rb in graph.role_bindings:
        if (rb.role_ref_kind, rb.role_ref_name) not in roles_bound:
            continue
        for s in rb.subjects:
            if s != subject:
                others.add(_subject_label(s))
    return tuple(sorted(others))


def assess_blast_radius(
    graph: ClusterGraph,
    *,
    target_namespace: str,
    target_service_name: str,
    subject: Subject,
) -> BlastRadiusAssessment:
    affected_services = _affected_services(graph, target_namespace, target_service_name)
    affected_subjects = _affected_subjects(graph, subject)
    total_affected = len(affected_services) + len(affected_subjects)

    if total_affected == 0:
        recommendation, reason = "GO", "namespace aislado por default-deny y sin RoleBinding compartido: contención segura e inmediata"
    elif total_affected <= 2:
        recommendation = "NARROW"
        reason = f"impacto colateral limitado ({total_affected} recurso(s)): contener con verificación dirigida"
    else:
        recommendation = "STOP"
        reason = f"impacto colateral amplio ({total_affected} recursos): requiere revisión humana antes de contener"

    return BlastRadiusAssessment(
        target_service=f"{target_namespace}/{target_service_name}",
        affected_services=affected_services,
        affected_subjects=affected_subjects,
        recommendation=recommendation,
        reason=reason,
    )
