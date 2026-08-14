"""ARG-012 / C-07.UC2 (Privilege escalation analysis): para cada subject
que aparece en algún RoleBinding/ClusterRoleBinding, evalúa sus
`effective_rules` (graph.effective_rules) contra un catálogo de
combinaciones verbo/recurso reconocidas como primitivas de escalada de
privilegio en RBAC de Kubernetes — no una heurística inventada: son las
mismas que documenta la comunidad de seguridad de Kubernetes (wildcard,
bind/escalate/impersonate sobre objetos RBAC, exec en pods, lectura de
secrets cluster-wide).

Ground truth F04 (documento maestro, 5.3): "Ruta ServiceAccount ->
RoleBinding/ClusterRole -> permiso excesivo y alcance afectado" — el
resultado reconstruye exactamente esa ruta, no solo el permiso final.
"""
from __future__ import annotations

import dataclasses

from graph import ClusterGraph, PolicyRule, Subject

# (recursos, verbos, motivo) — cualquier PolicyRule cuyos recursos/verbos
# tengan intersección no vacía con AMBOS conjuntos aquí se considera
# excesiva. "*" en la regla real cubre cualquier recurso/verbo del
# catálogo (comportamiento real de RBAC: un wildcard concede todo).
_DANGEROUS_PATTERNS: tuple[tuple[frozenset[str], frozenset[str], str], ...] = (
    (
        frozenset({"*"}),
        frozenset({"*"}),
        "wildcard total (apiGroups/resources/verbs = *): equivalente a cluster-admin",
    ),
    (
        frozenset({"roles", "clusterroles", "rolebindings", "clusterrolebindings"}),
        frozenset({"bind", "escalate", "impersonate", "*"}),
        "puede conceder o vincular permisos RBAC arbitrarios (bind/escalate/impersonate)",
    ),
    (
        frozenset({"pods/exec", "pods/attach"}),
        frozenset({"create", "*"}),
        "ejecución de comandos arbitrarios dentro de un pod (kubectl exec)",
    ),
    (
        frozenset({"secrets"}),
        frozenset({"get", "list", "watch", "*"}),
        "lectura de Secret en todo el alcance del binding (robo de credenciales)",
    ),
)


@dataclasses.dataclass(frozen=True)
class EscalationFinding:
    subject: str  # "namespace/nombre" o "nombre" (subjects sin namespace, p.ej. Group)
    path: str  # "ServiceAccount -> RoleBinding/ClusterRole -> permiso excesivo"
    rule: PolicyRule
    reason: str
    severity: str  # "critical" para wildcard total; "high" para el resto


def _rule_matches(rule: PolicyRule, resources: frozenset[str], verbs: frozenset[str]) -> bool:
    rule_resources = set(rule.resources)
    rule_verbs = set(rule.verbs)
    resource_hit = "*" in rule_resources or bool(rule_resources & resources)
    verb_hit = "*" in rule_verbs or bool(rule_verbs & verbs)
    return resource_hit and verb_hit


def _subject_label(subject: Subject) -> str:
    return f"{subject.namespace}/{subject.name}" if subject.namespace else subject.name


def find_privilege_escalations(graph: ClusterGraph) -> list[EscalationFinding]:
    seen_subjects: dict[Subject, None] = {}
    for binding in graph.role_bindings:
        for subject in binding.subjects:
            seen_subjects.setdefault(subject, None)

    findings: list[EscalationFinding] = []
    for subject in seen_subjects:
        for rule in graph.effective_rules(subject):
            for resources, verbs, reason in _DANGEROUS_PATTERNS:
                if not _rule_matches(rule, resources, verbs):
                    continue
                findings.append(
                    EscalationFinding(
                        subject=_subject_label(subject),
                        path=f"{subject.kind} -> RoleBinding/ClusterRole -> {reason}",
                        rule=rule,
                        reason=reason,
                        severity="critical" if resources == frozenset({"*"}) else "high",
                    )
                )
                # Un wildcard total subsume a los demás patrones (bind,
                # exec, secrets...): reportar los 4 por la MISMA regla es
                # ruido, no cuatro hallazgos distintos — un rule=(*,*,*)
                # ya implica todo lo demás.
                if resources == frozenset({"*"}) and verbs == frozenset({"*"}):
                    break
    return findings
