# sandbox/

Aislamiento de ejecución para los pods de `executors/`. Todo `executor` con `rollback_supported`/`execute` en su `tool_catalog` debe tener un perfil asignado aquí — un executor sin perfil no se despliega (`SECURITY.md`).

| Carpeta | Contenido |
| --- | --- |
| [`profiles/`](profiles/) | Composición: qué seccomp + AppArmor + NetworkPolicy + `securityContext` aplica a qué executor |
| [`seccomp/`](seccomp/) | Perfil seccomp real (`defaultAction: SCMP_ACT_ERRNO`, allowlist de syscalls) |
| [`apparmor/`](apparmor/) | Perfil AppArmor real (deniega `ptrace`, `mount`, `sys_admin`, `net_admin`) |
| [`network/`](network/) | `NetworkPolicy` de egress específica del executor, sobre la base default-deny de `argos-platform` |

`network/executor-egress.yaml` tiene una regla comentada a propósito (acceso al API server de Kubernetes): un `ipBlock: 0.0.0.0/0` habría anulado el egress-deny de todo el repositorio — queda pendiente de rellenar con el CIDR real del clúster (ARG-003), no con un comodín.
