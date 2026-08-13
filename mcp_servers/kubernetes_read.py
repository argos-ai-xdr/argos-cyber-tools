"""Servidor MCP de solo lectura hacia la API de Kubernetes (RBAC, pods,
manifests) — usado por el grafo de exposición (ARG-011), nunca por un
executor de escritura (eso vive en executors/kubernetes.py, con aprobación).
Interfaz real; cliente contra un clúster real pendiente de ARG-011.
"""
from __future__ import annotations

from typing import Protocol


class KubernetesReadServer(Protocol):
    def get_rbac_graph(self, *, namespace: str) -> dict: ...


class NotConfiguredKubernetesReadServer:
    def __init__(self, kubeconfig_path: str):
        self._kubeconfig_path = kubeconfig_path

    def get_rbac_graph(self, *, namespace: str) -> dict:
        raise NotImplementedError(
            f"Lectura de RBAC vía kubeconfig ({self._kubeconfig_path}) no "
            "implementada (ARG-011)."
        )
