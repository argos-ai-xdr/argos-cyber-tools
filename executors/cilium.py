"""Interfaz hacia el plano de red real (Cilium, argos-platform). En este
bootstrap, executors/kubernetes.py ya simula el efecto de una
CiliumNetworkPolicy con FakeClusterState — este módulo es el punto donde
conectar el cliente real contra la API de Cilium/Kubernetes cuando exista
un clúster (ARG-003/ARG-021), sin cambiar la interfaz que ya usan
KubernetesExecutor ni rollback/.
"""
from __future__ import annotations

from typing import Protocol


class CiliumClient(Protocol):
    def apply_network_policy(self, *, target: str, policy_name: str) -> None: ...

    def remove_network_policy(self, *, policy_name: str) -> None: ...


class NotConfiguredCiliumClient:
    def __init__(self, kubeconfig_path: str):
        self._kubeconfig_path = kubeconfig_path

    def apply_network_policy(self, *, target: str, policy_name: str) -> None:
        raise NotImplementedError(
            f"Cliente Cilium real (kubeconfig={self._kubeconfig_path}) no "
            "implementado (ARG-003/ARG-021); usar FakeClusterState de "
            "executors/kubernetes.py para desarrollo y tests."
        )

    def remove_network_policy(self, *, policy_name: str) -> None:
        raise NotImplementedError("ver apply_network_policy")
