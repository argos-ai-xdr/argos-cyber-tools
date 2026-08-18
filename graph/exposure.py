"""ARG-011 / C-07.UC1 (Exposure discovery): qué Service queda alcanzable
desde fuera del clúster (vía Ingress o NodePort/LoadBalancer) frente a los
que solo tienen ClusterIP — y contrasta lo expuesto contra la allowlist de
destino del escenario (mismo formato "namespace/nombre" que
policies/target-allowlists/, ver policies/target_allowlists.py).
"""
from __future__ import annotations

import dataclasses

from graph.model import ClusterGraph

_EXTERNALLY_REACHABLE_SERVICE_TYPES = {"NodePort", "LoadBalancer"}


@dataclasses.dataclass(frozen=True)
class ExposureFinding:
    service: str  # "namespace/nombre"
    exposure_type: str  # "ingress" | "nodeport" | "loadbalancer" | "internal"
    reachable_from: str  # "external" | "internal"
    in_allowlist: bool
    severity: str  # "high": externo y fuera de allowlist; si no, "low"


def discover_exposure(graph: ClusterGraph, target_allowlist: set[str]) -> list[ExposureFinding]:
    ingress_backends = {(ing.namespace, ing.backend_service) for ing in graph.ingresses}

    findings = []
    for (namespace, name), service in sorted(graph.services.items()):
        if (namespace, name) in ingress_backends:
            exposure_type, reachable_from = "ingress", "external"
        elif service.service_type in _EXTERNALLY_REACHABLE_SERVICE_TYPES:
            exposure_type, reachable_from = service.service_type.lower(), "external"
        else:
            exposure_type, reachable_from = "internal", "internal"

        in_allowlist = service.qualified_name in target_allowlist
        # No basta con "reachable_from == external": un servicio interno
        # tampoco debería estar fuera de la allowlist del escenario — pero
        # solo se marca "high" cuando además es alcanzable desde fuera,
        # que es el caso realmente explotable sin acceso previo al clúster.
        severity = "high" if reachable_from == "external" and not in_allowlist else "low"

        findings.append(
            ExposureFinding(
                service=service.qualified_name,
                exposure_type=exposure_type,
                reachable_from=reachable_from,
                in_allowlist=in_allowlist,
                severity=severity,
            )
        )
    return findings
