from __future__ import annotations

from graph import Subject, build_graph
from graph.blast_radius import assess_blast_radius

SERVICE_TARGET = {
    "kind": "Service",
    "metadata": {"name": "gseg-simulado", "namespace": "argos-cyber-range"},
    "spec": {"type": "ClusterIP", "selector": {"app": "gseg-simulado"}, "ports": [{"port": 8080}]},
}
SERVICE_SIBLING_1 = {
    "kind": "Service",
    "metadata": {"name": "sibling-1", "namespace": "argos-cyber-range"},
    "spec": {"type": "ClusterIP", "selector": {"app": "sibling-1"}, "ports": [{"port": 80}]},
}
SERVICE_SIBLING_2 = {
    "kind": "Service",
    "metadata": {"name": "sibling-2", "namespace": "argos-cyber-range"},
    "spec": {"type": "ClusterIP", "selector": {"app": "sibling-2"}, "ports": [{"port": 80}]},
}
DEFAULT_DENY_POLICY = {
    "kind": "NetworkPolicy",
    "metadata": {"name": "default-deny", "namespace": "argos-cyber-range"},
    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
}
CLUSTER_ROLE = {
    "kind": "ClusterRole",
    "metadata": {"name": "shared-role"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}
BINDING_TWO_SUBJECTS = {
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "shared-binding"},
    "roleRef": {"kind": "ClusterRole", "name": "shared-role"},
    "subjects": [
        {"kind": "ServiceAccount", "name": "gseg-simulado-sa", "namespace": "argos-cyber-range"},
        {"kind": "ServiceAccount", "name": "co-tenant-sa", "namespace": "argos-cyber-range"},
    ],
}

TARGET_SUBJECT = Subject(kind="ServiceAccount", name="gseg-simulado-sa", namespace="argos-cyber-range")


def test_namespace_isolated_by_default_deny_and_no_shared_bindings_is_go():
    graph = build_graph([SERVICE_TARGET, SERVICE_SIBLING_1, DEFAULT_DENY_POLICY])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert result.recommendation == "GO"
    assert result.affected_services == ()
    assert result.affected_subjects == ()


def test_namespace_without_default_deny_with_few_siblings_is_narrow():
    graph = build_graph([SERVICE_TARGET, SERVICE_SIBLING_1])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert result.recommendation == "NARROW"
    assert result.affected_services == ("argos-cyber-range/sibling-1",)


def test_namespace_without_default_deny_and_shared_rolebinding_is_stop():
    """Regresión conceptual del escenario ARGOS-CYB-01: un namespace sin
    default-deny Y un ServiceAccount cuyo rol comparte otro subject
    (co-tenant) es exactamente el caso de mayor impacto colateral — no
    debe recomendarse contención automática (STOP, no GO/NARROW)."""
    graph = build_graph([SERVICE_TARGET, SERVICE_SIBLING_1, SERVICE_SIBLING_2, CLUSTER_ROLE, BINDING_TWO_SUBJECTS])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert result.recommendation == "STOP"
    assert set(result.affected_services) == {"argos-cyber-range/sibling-1", "argos-cyber-range/sibling-2"}
    assert result.affected_subjects == ("argos-cyber-range/co-tenant-sa",)


def test_shared_binding_does_not_include_the_target_subject_itself():
    graph = build_graph([SERVICE_TARGET, DEFAULT_DENY_POLICY, CLUSTER_ROLE, BINDING_TWO_SUBJECTS])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert "argos-cyber-range/gseg-simulado-sa" not in result.affected_subjects
    assert result.affected_subjects == ("argos-cyber-range/co-tenant-sa",)


def test_evidence_refs_include_examined_network_policy_and_role_binding():
    """Propuesta v0.6.25.4 (12.13): 'reglas, incertidumbre y evidence_refs
    obligatorios' — evidence_refs debe apuntar a lo REALMENTE examinado
    (nombres reales del grafo), no a un placeholder genérico."""
    graph = build_graph([SERVICE_TARGET, DEFAULT_DENY_POLICY, CLUSTER_ROLE, BINDING_TWO_SUBJECTS])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert "networkpolicy/argos-cyber-range/default-deny" in result.evidence_refs
    assert "clusterrolebinding/cluster/shared-binding" in result.evidence_refs


def test_evidence_refs_empty_when_nothing_to_examine():
    graph = build_graph([SERVICE_TARGET])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert result.evidence_refs == ()


def test_uncertainty_note_is_never_empty_even_when_recommendation_is_go():
    """'GO' nunca debe leerse como una garantía absoluta: la nota de
    incertidumbre (TRUE/FALSE/UNKNOWN) debe acompañar cualquier
    recomendación, incluida la más favorable."""
    graph = build_graph([SERVICE_TARGET, DEFAULT_DENY_POLICY])
    result = assess_blast_radius(
        graph, target_namespace="argos-cyber-range", target_service_name="gseg-simulado", subject=TARGET_SUBJECT
    )
    assert result.recommendation == "GO"
    assert result.uncertainty
    assert "cross-namespace" in result.uncertainty
