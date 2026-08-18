"""Modelo de datos real de `graph` (RBAC + red) y `build_graph`.

Separado de `graph/__init__.py` a propósito (2026-08-18): las
submódulos de este paquete (`escalation.py`, `blast_radius.py`,
`exposure.py`) necesitan `ClusterGraph`/`Subject`/`PolicyRule` -- si
esas clases viven en `graph/__init__.py` y los submódulos hacen
`from graph import X` (importando de vuelta desde su propio paquete
padre), el import es frágil ante ciertos mecanismos de instalación
editable (encontrado en un run real de CI, no reproducible en local:
`ImportError: cannot import name 'ClusterGraph' from 'graph' (unknown
location)`). Importar siempre desde un submódulo hermano
(`graph.model`), nunca desde el paquete padre, elimina la fragilidad
estructuralmente en vez de depender de un orden de import concreto.
`graph/__init__.py` sigue re-exportando todo esto -- `from graph import
X` externo (tests, otros repos) no cambia.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Subject:
    kind: str  # ServiceAccount | User | Group
    name: str
    namespace: str | None = None


@dataclasses.dataclass(frozen=True)
class PolicyRule:
    api_groups: tuple[str, ...]
    resources: tuple[str, ...]
    verbs: tuple[str, ...]
    resource_names: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class RoleDef:
    kind: str  # Role | ClusterRole
    name: str
    namespace: str | None  # None para ClusterRole
    rules: tuple[PolicyRule, ...]

    @property
    def key(self) -> tuple[str, str, str | None]:
        return (self.kind, self.name, self.namespace)


@dataclasses.dataclass(frozen=True)
class RoleBindingDef:
    kind: str  # RoleBinding | ClusterRoleBinding
    name: str
    namespace: str | None  # None para ClusterRoleBinding
    role_ref_kind: str  # Role | ClusterRole
    role_ref_name: str
    subjects: tuple[Subject, ...]


@dataclasses.dataclass(frozen=True)
class ServiceDef:
    name: str
    namespace: str
    selector: tuple[tuple[str, str], ...]
    service_type: str  # ClusterIP | NodePort | LoadBalancer
    ports: tuple[int, ...]

    @property
    def qualified_name(self) -> str:
        return f"{self.namespace}/{self.name}"


@dataclasses.dataclass(frozen=True)
class IngressDef:
    name: str
    namespace: str
    backend_service: str
    host: str | None


@dataclasses.dataclass(frozen=True)
class NetworkPolicyDef:
    name: str
    namespace: str
    pod_selector: tuple[tuple[str, str], ...]
    is_default_deny: bool


class InvalidManifest(Exception):
    pass


@dataclasses.dataclass
class ClusterGraph:
    roles: dict[tuple[str, str, str | None], RoleDef] = dataclasses.field(default_factory=dict)
    role_bindings: list[RoleBindingDef] = dataclasses.field(default_factory=list)
    services: dict[tuple[str, str], ServiceDef] = dataclasses.field(default_factory=dict)
    ingresses: list[IngressDef] = dataclasses.field(default_factory=list)
    network_policies: list[NetworkPolicyDef] = dataclasses.field(default_factory=list)

    def role(self, kind: str, name: str, namespace: str | None) -> RoleDef | None:
        return self.roles.get((kind, name, namespace))

    def bindings_for_subject(self, subject: Subject) -> list[RoleBindingDef]:
        return [rb for rb in self.role_bindings if subject in rb.subjects]

    def effective_rules(self, subject: Subject) -> list[PolicyRule]:
        """Todas las PolicyRule alcanzables por un subject a través de sus
        RoleBinding/ClusterRoleBinding — ARG-012 las analiza para detectar
        privilegio excesivo. Un RoleBinding a un ClusterRole aplica solo
        dentro del namespace del propio binding (no en todo el clúster);
        eso es distinto de un ClusterRoleBinding, que sí es cluster-wide —
        confundir los dos sobreestimaría o subestimaría el alcance real."""
        rules: list[PolicyRule] = []
        for rb in self.bindings_for_subject(subject):
            role_namespace = rb.namespace if rb.role_ref_kind == "Role" else None
            role = self.role(rb.role_ref_kind, rb.role_ref_name, role_namespace)
            if role is not None:
                rules.extend(role.rules)
        return rules


def _metadata(manifest: dict, field: str, *, required_namespace: bool) -> tuple[str, str | None]:
    metadata = manifest.get("metadata", {})
    name = metadata.get("name")
    if not name:
        raise InvalidManifest(f"{field}: falta metadata.name")
    namespace = metadata.get("namespace")
    if required_namespace and not namespace:
        raise InvalidManifest(f"{field} {name!r}: falta metadata.namespace")
    return name, namespace


def _add_role(graph: ClusterGraph, manifest: dict) -> None:
    kind = manifest["kind"]
    name, namespace = _metadata(manifest, kind, required_namespace=(kind == "Role"))
    if kind == "ClusterRole":
        namespace = None
    rules = tuple(
        PolicyRule(
            api_groups=tuple(r.get("apiGroups", [])),
            resources=tuple(r.get("resources", [])),
            verbs=tuple(r.get("verbs", [])),
            resource_names=tuple(r.get("resourceNames", [])),
        )
        for r in manifest.get("rules", [])
    )
    role = RoleDef(kind=kind, name=name, namespace=namespace, rules=rules)
    graph.roles[role.key] = role


def _add_role_binding(graph: ClusterGraph, manifest: dict) -> None:
    kind = manifest["kind"]
    name, namespace = _metadata(manifest, kind, required_namespace=(kind == "RoleBinding"))
    if kind == "ClusterRoleBinding":
        namespace = None
    role_ref = manifest.get("roleRef")
    if not role_ref or "kind" not in role_ref or "name" not in role_ref:
        raise InvalidManifest(f"{kind} {name!r}: falta roleRef.kind/roleRef.name")
    subjects = tuple(
        Subject(kind=s["kind"], name=s["name"], namespace=s.get("namespace"))
        for s in manifest.get("subjects", [])
    )
    graph.role_bindings.append(
        RoleBindingDef(
            kind=kind,
            name=name,
            namespace=namespace,
            role_ref_kind=role_ref["kind"],
            role_ref_name=role_ref["name"],
            subjects=subjects,
        )
    )


def _add_service(graph: ClusterGraph, manifest: dict) -> None:
    name, namespace = _metadata(manifest, "Service", required_namespace=True)
    spec = manifest.get("spec", {})
    selector = tuple(sorted(spec.get("selector", {}).items()))
    ports = tuple(p["port"] for p in spec.get("ports", []) if "port" in p)
    service = ServiceDef(
        name=name,
        namespace=namespace,  # type: ignore[arg-type]
        selector=selector,
        service_type=spec.get("type", "ClusterIP"),
        ports=ports,
    )
    graph.services[(namespace, name)] = service  # type: ignore[index]


def _add_ingress(graph: ClusterGraph, manifest: dict) -> None:
    name, namespace = _metadata(manifest, "Ingress", required_namespace=True)
    spec = manifest.get("spec", {})
    for rule in spec.get("rules", [{}]):
        host = rule.get("host")
        for path in rule.get("http", {}).get("paths", [{}]):
            backend_service = path.get("backend", {}).get("service", {}).get("name")
            if backend_service:
                graph.ingresses.append(
                    IngressDef(name=name, namespace=namespace, backend_service=backend_service, host=host)  # type: ignore[arg-type]
                )


def _add_network_policy(graph: ClusterGraph, manifest: dict) -> None:
    name, namespace = _metadata(manifest, "NetworkPolicy", required_namespace=True)
    spec = manifest.get("spec", {})
    pod_selector = tuple(sorted(spec.get("podSelector", {}).get("matchLabels", {}).items()))
    policy_types = spec.get("policyTypes", [])
    is_default_deny = ("Ingress" in policy_types and not spec.get("ingress")) or (
        "Egress" in policy_types and not spec.get("egress")
    )
    graph.network_policies.append(
        NetworkPolicyDef(
            name=name,
            namespace=namespace,  # type: ignore[arg-type]
            pod_selector=pod_selector,
            is_default_deny=is_default_deny,
        )
    )


_HANDLERS = {
    "Role": _add_role,
    "ClusterRole": _add_role,
    "RoleBinding": _add_role_binding,
    "ClusterRoleBinding": _add_role_binding,
    "Service": _add_service,
    "Ingress": _add_ingress,
    "NetworkPolicy": _add_network_policy,
}


def build_graph(manifests: list[dict]) -> ClusterGraph:
    """Otros kinds (Deployment, Pod, ServiceAccount) se ignoran a propósito:
    no aportan al grafo RBAC/exposición (ARG-011 se centra en permisos y
    alcance de red — un ServiceAccount sin RoleBinding no tiene privilegio
    que analizar, y su existencia como objeto no cambia esa conclusión)."""
    graph = ClusterGraph()
    for manifest in manifests:
        handler = _HANDLERS.get(manifest.get("kind", ""))
        if handler is not None:
            handler(graph, manifest)
    return graph
