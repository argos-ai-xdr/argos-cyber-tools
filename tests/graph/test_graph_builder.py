from __future__ import annotations

import pytest

from graph import InvalidManifest, PolicyRule, Subject, build_graph

CLUSTER_ROLE_EXCESSIVE = {
    "kind": "ClusterRole",
    "metadata": {"name": "gseg-excessive"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}

ROLE_SCOPED = {
    "kind": "Role",
    "metadata": {"name": "gseg-reader", "namespace": "argos-cyber-range"},
    "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
}

CLUSTER_ROLE_BINDING = {
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "gseg-excessive-binding"},
    "roleRef": {"kind": "ClusterRole", "name": "gseg-excessive"},
    "subjects": [{"kind": "ServiceAccount", "name": "gseg-simulado-sa", "namespace": "argos-cyber-range"}],
}

ROLE_BINDING = {
    "kind": "RoleBinding",
    "metadata": {"name": "gseg-reader-binding", "namespace": "argos-cyber-range"},
    "roleRef": {"kind": "Role", "name": "gseg-reader"},
    "subjects": [{"kind": "ServiceAccount", "name": "gseg-reader-sa", "namespace": "argos-cyber-range"}],
}


def test_build_graph_parses_cluster_role_and_binding():
    graph = build_graph([CLUSTER_ROLE_EXCESSIVE, CLUSTER_ROLE_BINDING])
    role = graph.role("ClusterRole", "gseg-excessive", None)
    assert role is not None
    assert role.rules == (PolicyRule(api_groups=("*",), resources=("*",), verbs=("*",)),)
    assert len(graph.role_bindings) == 1


def test_effective_rules_resolves_clusterrolebinding_across_cluster():
    graph = build_graph([CLUSTER_ROLE_EXCESSIVE, CLUSTER_ROLE_BINDING])
    subject = Subject(kind="ServiceAccount", name="gseg-simulado-sa", namespace="argos-cyber-range")
    rules = graph.effective_rules(subject)
    assert len(rules) == 1
    assert rules[0].verbs == ("*",)


def test_rolebinding_to_role_is_scoped_to_binding_namespace():
    """Un RoleBinding solo puede apuntar a un Role del MISMO namespace —
    a diferencia de un ClusterRoleBinding, que aplica en todo el clúster."""
    graph = build_graph([ROLE_SCOPED, ROLE_BINDING])
    subject = Subject(kind="ServiceAccount", name="gseg-reader-sa", namespace="argos-cyber-range")
    rules = graph.effective_rules(subject)
    assert len(rules) == 1
    assert rules[0].verbs == ("get", "list")


def test_subject_without_bindings_has_no_effective_rules():
    graph = build_graph([CLUSTER_ROLE_EXCESSIVE, CLUSTER_ROLE_BINDING])
    unrelated = Subject(kind="ServiceAccount", name="someone-else", namespace="argos-cyber-range")
    assert graph.effective_rules(unrelated) == []


def test_unrelated_manifest_kinds_are_ignored():
    graph = build_graph([{"kind": "Pod", "metadata": {"name": "x", "namespace": "n"}}])
    assert graph.roles == {}
    assert graph.services == {}


def test_role_without_namespace_is_rejected():
    bad = {"kind": "Role", "metadata": {"name": "no-namespace"}, "rules": []}
    with pytest.raises(InvalidManifest):
        build_graph([bad])


def test_role_binding_without_role_ref_is_rejected():
    bad = {
        "kind": "RoleBinding",
        "metadata": {"name": "broken", "namespace": "argos-cyber-range"},
        "subjects": [],
    }
    with pytest.raises(InvalidManifest):
        build_graph([bad])
