from __future__ import annotations

from graph import build_graph
from graph.escalation import find_privilege_escalations

# Escenario ARGOS-CYB-01 (5.1): "ServiceAccount con RBAC excesivo" ligado
# a gseg-simulado.
CLUSTER_ROLE_WILDCARD = {
    "kind": "ClusterRole",
    "metadata": {"name": "gseg-excessive"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}
BINDING_WILDCARD = {
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "gseg-excessive-binding"},
    "roleRef": {"kind": "ClusterRole", "name": "gseg-excessive"},
    "subjects": [{"kind": "ServiceAccount", "name": "gseg-simulado-sa", "namespace": "argos-cyber-range"}],
}

ROLE_EXEC = {
    "kind": "Role",
    "metadata": {"name": "debug-exec", "namespace": "argos-cyber-range"},
    "rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}],
}
BINDING_EXEC = {
    "kind": "RoleBinding",
    "metadata": {"name": "debug-exec-binding", "namespace": "argos-cyber-range"},
    "roleRef": {"kind": "Role", "name": "debug-exec"},
    "subjects": [{"kind": "ServiceAccount", "name": "debugger-sa", "namespace": "argos-cyber-range"}],
}

ROLE_READER = {
    "kind": "Role",
    "metadata": {"name": "gseg-reader", "namespace": "argos-cyber-range"},
    "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
}
BINDING_READER = {
    "kind": "RoleBinding",
    "metadata": {"name": "gseg-reader-binding", "namespace": "argos-cyber-range"},
    "roleRef": {"kind": "Role", "name": "gseg-reader"},
    "subjects": [{"kind": "ServiceAccount", "name": "reader-sa", "namespace": "argos-cyber-range"}],
}


def test_wildcard_grant_reported_once_as_critical_not_four_times():
    """Regresión: un rule=(*,*,*) coincidía con los 4 patrones peligrosos
    (wildcard, bind/escalate, exec, secrets) y generaba 4 hallazgos
    redundantes para el MISMO permiso — un wildcard ya subsume a los
    demás, así que debe reportarse una sola vez."""
    graph = build_graph([CLUSTER_ROLE_WILDCARD, BINDING_WILDCARD])
    findings = find_privilege_escalations(graph)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].subject == "argos-cyber-range/gseg-simulado-sa"
    assert "ServiceAccount -> RoleBinding/ClusterRole" in findings[0].path


def test_pods_exec_create_is_flagged_high_not_critical():
    graph = build_graph([ROLE_EXEC, BINDING_EXEC])
    findings = find_privilege_escalations(graph)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "exec" in findings[0].reason


def test_read_only_scoped_role_is_not_flagged():
    graph = build_graph([ROLE_READER, BINDING_READER])
    assert find_privilege_escalations(graph) == []


def test_subject_with_no_bindings_produces_no_findings():
    graph = build_graph([CLUSTER_ROLE_WILDCARD])  # sin binding
    assert find_privilege_escalations(graph) == []


def test_multiple_subjects_evaluated_independently():
    graph = build_graph([CLUSTER_ROLE_WILDCARD, BINDING_WILDCARD, ROLE_READER, BINDING_READER])
    findings = find_privilege_escalations(graph)
    subjects = {f.subject for f in findings}
    assert subjects == {"argos-cyber-range/gseg-simulado-sa"}
