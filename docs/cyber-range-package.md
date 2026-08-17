# Paquete Cyber-range (ARG-028)

ARG-028 (S8, propuesta v0.6.25.4 §16.7) define el paquete **"Cyber-range:
RoE, allowlists, init/reset, kill switch, limpieza, prohibiciones y
evidencias"**, validado por "Emulación + aborto seguro" — y en su
desglose por repositorio (§16.8) fija el artefacto final de este repo
como **"range acceptance bundle"**. La implementación operativa del rango
en sí (namespaces, scripts) vive en `argos-platform`; este documento
consolida las piezas dispersas en un solo lugar consultable, cita el
archivo real de cada una, y señala explícitamente lo que sigue siendo
plantilla sin rellenar.

## RoE (Rules of Engagement)

`argos-contracts-scenarios/scenarios/ARGOS-CYB-01/scenario.yaml` — no
prosa aparte, es el archivo real que consume el harness:

* **Entorno**: cyber-range aislado en Kubernetes, namespace
  `argos-cyber-range`; egress denegado salvo repositorios y endpoints
  sinkhole aprobados.
* **Actor**: emulación controlada (Atomic Red Team/Kubernetes Goat o
  scripts propios revisados); sin explotación contra activos externos.
* **Prohibiciones explícitas** (`out_of_scope`): persistencia real,
  malware activo, credenciales productivas, Internet abierto, cambios en
  GSEG real, contención autónoma no aprobada.
* **Límites de seguridad** (`constraints`, 7 reglas): infraestructura
  reproducible por manifests versionados y fijada por commit/digest;
  IoCs/CVE/ATT&CK/EPSS como snapshots con fecha y hash (sin resultados
  variables por consulta online); allowlist cerrada (todo destino no
  incluido produce `DENY`); primera ejecución de cualquier remediación
  SIEMPRE en dry-run, `EXECUTE` exige aprobación humana vinculada al
  `action_id`; contención limitada a `CiliumNetworkPolicy` temporal o
  escalar a cero un deployment de laboratorio, eliminación irreversible
  prohibida; kill switch y rollback independientes del agente, reintentos
  idempotentes; sin chain-of-thought almacenado — solo inputs,
  herramientas, evidencias, decisión, política y aprobación.

Zona de máximo aislamiento (`argos-control/architecture/trust-zones/trust-zones.md`):
cualquier conexión no listada en la tabla de zonas de confianza produce
`DENY` por defecto.

## Allowlists — dos capas distintas, con estados MUY distintos

1. **Por tool** (`policies/target-allowlists/*.yaml`, este repo): REAL y
   rellena. `isolate_kubernetes_workload` y `scale_to_zero` solo permiten
   `deployment/gseg-simulado`. Aplicada de verdad por
   `mcp_gateway.Gateway.authorize()`, probada en
   `tests/graph/test_attack_path.py::test_target_outside_allowlist_is_out_of_scope`.
2. **Por rango** (`argos-platform/cyber-range/targets/allowlist.yaml`):
   **sigue siendo plantilla — `approved_repositories`,
   `sinkhole_endpoints` y `targets` son todos `"TODO"` literales**.
   `bootstrap.sh` tiene su propio `TODO` pendiente de aplicar las
   `CiliumNetworkPolicy` generadas a partir de este archivo. Cambiarlo
   exige revisión de `qa-security-observer` (CODEOWNERS) — no se rellena
   aquí con valores inventados, es una decisión de seguridad real que le
   corresponde a ese rol.

**No confundir las dos**: la capa 1 gobierna qué puede hacer una TOOL ya
autorizada a ejecutar; la capa 2 gobierna qué existe siquiera dentro del
rango. La capa 1 está lista para G3; la capa 2 bloquea que el rango se
despliegue de verdad (mismo bloqueo raíz que ENV-QUAL-01).

## Init / Reset / Limpieza

`argos-platform/cyber-range/`:

* **Init**: `bootstrap/bootstrap.sh` — namespace + `default-deny-all` +
  cuotas, idempotente (ARG-003). Aplica los manifests reales de
  `kubernetes/namespaces/argos-cyber-range.yaml` y
  `kubernetes/network-policies/default-deny.yaml`.
* **Reset** ("limpieza"): `reset/reset.sh` — borra el namespace completo
  y lo reconstruye desde `bootstrap.sh`. No hay un mecanismo de limpieza
  distinto del reset completo (no existe un "cleanup parcial" en ningún
  repo, verificado) — reproducible por diseño: "dos resets consecutivos
  deben producir el mismo resultado" (checklist, referencia directa a
  AC01). El propio script tiene un `TODO` pendiente (ARG-003): confirmar
  que el estado post-reset coincide con un baseline hash esperado — hoy
  no lo verifica, solo reconstruye.

## Kill switch

`argos-platform/cyber-range/kill-switch/kill-switch.sh` — corta TODO el
egress no esencial (elimina cualquier `NetworkPolicy` salvo
`default-deny-all`) y escala a cero todos los `Deployment` del namespace.
Contiene un fix real de esta línea de trabajo: bajo `set -o pipefail`,
`grep -v "default-deny-all"` sin coincidencias (el caso NORMAL — sin
ninguna excepción activa) salía con status 1 y abortaba el script ANTES
de llegar al paso 2 (escalar a cero), el peor momento posible para que un
kill switch falle en silencio — corregido con `{ grep -v ... || true; }`.
Cualquier rol puede invocarlo, no solo quien opera el agente — así lo
documenta el propio script en su comentario de cabecera. La matriz real
(`argos-control/governance/policies/segregation-of-duties.md`) no
menciona el kill switch por su nombre, pero es consistente con ella: el
Security Observer puede "verificar gates, integridad del evidence pack y
segregación" sin poder "operar el agente" — el kill switch corta egress y
escala a cero, no opera el agente ni ejecuta una acción del catálogo, así
que no choca con esa restricción.

## Prohibiciones

Ver "RoE" arriba (`out_of_scope` de `scenario.yaml`) — no se duplica una
segunda lista aquí para evitar que las dos diverjan con el tiempo.

## Evidencias

* `EvidenceManifest v1` (contrato cerrado,
  `argos-contracts-scenarios/schemas/evidence-manifest/`) + el manifiesto
  del propio run de validación
  (`argos-validation/harness/evidence/manifest.py`, sha256 real sobre el
  `run_summary.json`).
* `cyber-range/validation/checklist.md` (argos-platform): 7 puntos de
  verificación tras `bootstrap.sh`/`reset.sh`, evidencia de entrada de G3
  — namespace con Pod Security `restricted`, `default-deny-all` como
  única política salvo excepciones declaradas, al menos un caso negativo
  probado (destino fuera de allowlist → `DENY`), reset reproducible,
  kill-switch dentro de timeout, ningún target con acceso a namespaces
  productivos, ejecución con `run_id`. **Esta checklist nunca se ha
  ejecutado contra un cluster real** — es un checklist real y completo,
  sin resultados reales todavía (mismo bloqueo que ENV-QUAL-01).

## Estado real: "Emulación + aborto seguro" (criterio de validación del paquete)

* **Aborto seguro**: SÍ probado — el kill switch es código real,
  revisado línea a línea, con su bug de `pipefail` encontrado y
  corregido (arriba). Sin ejecutar contra un cluster real, pero la
  lógica en sí no depende de que exista uno para estar correcta.
* **Emulación**: la allowlist de CAPA TOOL (autorización de acciones) es
  real; la allowlist de CAPA RANGO (qué existe en el rango) sigue sin
  rellenar. No se puede afirmar "emulación lista" mientras
  `targets/allowlist.yaml` siga en `TODO` — este es el gap concreto que
  bloquea el paquete, no una vaguedad de "falta cluster real".
