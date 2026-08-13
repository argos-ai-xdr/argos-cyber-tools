"""Carga policies/target-allowlists/*.yaml como el dict {tool_name: {targets}}
que mcp_gateway.Gateway usa por defecto — mismo patrón que
tool_catalog.load_catalog() para el catálogo. Antes de esto, el dato de
policies/target-allowlists/ (que el propio README de policies/ describe como
"Misma allowlist que opa/, en forma de datos para que mcp_gateway (Python)
no tenga que parsear Rego") nunca se cargaba desde ningún sitio: Gateway
solo lo recibía si el caller lo pasaba explícitamente a mano, duplicando el
mismo dato que ya vive aquí — sin ese wiring, Gateway() sin argumentos
denegaba TODO target-allowlisted (target_allowlists quedaba en {}), no
porque el target realmente no estuviera permitido, sino porque nadie leía
el YAML que sí lo dice.
"""
from __future__ import annotations

import pathlib

import yaml

_ALLOWLISTS_DIR = pathlib.Path(__file__).resolve().parent / "target-allowlists"


def load_target_allowlists(directory: pathlib.Path | None = None) -> dict[str, set[str]]:
    allowlists: dict[str, set[str]] = {}
    for path in sorted((directory or _ALLOWLISTS_DIR).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        allowlists[data["tool"]] = set(data["allowlist"])
    return allowlists
