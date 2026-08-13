# mcp_servers/

Servidores de **solo lectura**. Ninguno escribe estado ni ejecuta acciones — eso vive en `../executors/`, siempre detrás de `mcp_gateway` y `policies/approval`.

| Módulo | Alimenta a | Estado |
| --- | --- | --- |
| [`assets.py`](assets.py) | `read_asset_inventory` | Real (`InMemoryAssetServer`) |
| [`vulnerabilities.py`](vulnerabilities.py) | `read_vulnerability_findings` | Real (`InMemoryVulnerabilityServer`) |
| [`cti.py`](cti.py) | Grounding CTI (AC08) | Interfaz, pendiente ARG-016 |
| [`kubernetes_read.py`](kubernetes_read.py) | Grafo de exposición (ARG-011) | Interfaz, pendiente ARG-011 |
| [`network_read.py`](network_read.py) | Grafo de exposición / blast radius | Interfaz, pendiente ARG-011 |
| [`evidence_read.py`](evidence_read.py) | Consulta de `EvidenceManifest` | Interfaz, pendiente ARG-023 |

Todo servidor pasa igualmente por `mcp_gateway.Gateway.authorize` (scope `cyber.read.*`) — "solo lectura" no significa "sin control de acceso".
