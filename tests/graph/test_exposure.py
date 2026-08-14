from __future__ import annotations

from graph import build_graph
from graph.exposure import discover_exposure

SERVICE_GSEG = {
    "kind": "Service",
    "metadata": {"name": "gseg-simulado", "namespace": "argos-cyber-range"},
    "spec": {"type": "ClusterIP", "selector": {"app": "gseg-simulado"}, "ports": [{"port": 8080}]},
}

SERVICE_UNEXPECTED_NODEPORT = {
    "kind": "Service",
    "metadata": {"name": "debug-console", "namespace": "argos-cyber-range"},
    "spec": {"type": "NodePort", "selector": {"app": "debug-console"}, "ports": [{"port": 9000}]},
}

INGRESS_FOR_GSEG = {
    "kind": "Ingress",
    "metadata": {"name": "gseg-ingress", "namespace": "argos-cyber-range"},
    "spec": {
        "rules": [
            {
                "host": "gseg.lab.internal",
                "http": {"paths": [{"backend": {"service": {"name": "gseg-simulado"}}}]},
            }
        ]
    },
}


def test_service_without_ingress_or_external_type_is_internal():
    graph = build_graph([SERVICE_GSEG])
    findings = discover_exposure(graph, target_allowlist={"argos-cyber-range/gseg-simulado"})
    assert len(findings) == 1
    assert findings[0].exposure_type == "internal"
    assert findings[0].reachable_from == "internal"
    assert findings[0].severity == "low"


def test_service_behind_ingress_is_external_and_in_allowlist_is_low_severity():
    graph = build_graph([SERVICE_GSEG, INGRESS_FOR_GSEG])
    findings = discover_exposure(graph, target_allowlist={"argos-cyber-range/gseg-simulado"})
    finding = findings[0]
    assert finding.exposure_type == "ingress"
    assert finding.reachable_from == "external"
    assert finding.in_allowlist is True
    assert finding.severity == "low"


def test_unexpected_nodeport_outside_allowlist_is_high_severity():
    """Regresión conceptual del escenario ARGOS-CYB-01: un servicio nuevo,
    no autorizado y alcanzable desde fuera (p. ej. un debug console
    olvidado) debe marcarse explícitamente como hallazgo de severidad alta,
    no pasar desapercibido junto a los servicios legítimos."""
    graph = build_graph([SERVICE_GSEG, SERVICE_UNEXPECTED_NODEPORT])
    findings = discover_exposure(graph, target_allowlist={"argos-cyber-range/gseg-simulado"})
    by_service = {f.service: f for f in findings}

    assert by_service["argos-cyber-range/debug-console"].exposure_type == "nodeport"
    assert by_service["argos-cyber-range/debug-console"].reachable_from == "external"
    assert by_service["argos-cyber-range/debug-console"].in_allowlist is False
    assert by_service["argos-cyber-range/debug-console"].severity == "high"

    assert by_service["argos-cyber-range/gseg-simulado"].severity == "low"


def test_no_services_produces_no_findings():
    graph = build_graph([])
    assert discover_exposure(graph, target_allowlist=set()) == []
