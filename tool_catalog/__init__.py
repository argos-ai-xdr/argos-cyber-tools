"""Carga y valida el catálogo de herramientas (documento maestro v0.5,
"Definición obligatoria de cada tool"). mcp_gateway y policies/approval
importan este módulo para saber, por herramienta, si requiere aprobación,
allowlist de destino y evidencia — nunca lo asumen por su cuenta.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib

import yaml
from jsonschema import Draft202012Validator

from tool_catalog.signatures import verify_integrity_manifest

_SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schemas" / "tool-definition.schema.json"
_DEFINITIONS_DIR = pathlib.Path(__file__).resolve().parent / "definitions"
_MANIFEST_PATH = pathlib.Path(__file__).resolve().parent / "signatures" / "catalog.manifest.json"


class InvalidToolDefinition(Exception):
    def __init__(self, path: pathlib.Path, errors: list[str]):
        super().__init__(f"{path}: {errors}")
        self.path = path
        self.errors = errors


class ToolNotFound(KeyError):
    pass


class CatalogIntegrityError(Exception):
    """tool_catalog/signatures/ ya implementaba y probaba
    verify_integrity_manifest, pero load_catalog() nunca lo invocaba — el
    catálogo real que usa mcp_gateway.Gateway para autorizar llamadas se
    cargaba sin comprobar integridad en absoluto, pese a que el docstring de
    tool_catalog/signatures/__init__.py ya documentaba esa comprobación como
    el propósito del módulo."""

    def __init__(self, mismatches: list[str]):
        super().__init__(f"Integridad del catálogo comprometida: {mismatches}")
        self.mismatches = mismatches


@dataclasses.dataclass(frozen=True)
class ToolDefinition:
    name: str
    version: str
    risk_level: str
    mode: tuple[str, ...]
    required_scope: str
    approval_required: bool
    idempotent: bool
    timeout_seconds: int
    target_allowlist_required: bool
    rollback_supported: bool
    evidence_required: bool

    @classmethod
    def from_dict(cls, data: dict) -> ToolDefinition:
        return cls(
            name=data["name"],
            version=data["version"],
            risk_level=data["risk_level"],
            mode=tuple(data["mode"]),
            required_scope=data["required_scope"],
            approval_required=data["approval_required"],
            idempotent=data["idempotent"],
            timeout_seconds=data["timeout_seconds"],
            target_allowlist_required=data["target_allowlist_required"],
            rollback_supported=data["rollback_supported"],
            evidence_required=data["evidence_required"],
        )


def _load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def load_definition(path: pathlib.Path) -> ToolDefinition:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(_load_schema())
    errors = [e.message for e in validator.iter_errors(data)]
    if errors:
        raise InvalidToolDefinition(path, errors)
    return ToolDefinition.from_dict(data)


def load_catalog(
    definitions_dir: pathlib.Path | None = None,
    *,
    manifest_path: pathlib.Path | None = None,
) -> dict[str, ToolDefinition]:
    directory = definitions_dir or _DEFINITIONS_DIR

    # Solo se exige el manifiesto por defecto cuando se usa el directorio de
    # definiciones por defecto: un definitions_dir explícito (tests, catálogos
    # sintéticos) no tiene un manifiesto correspondiente y no debería
    # obligarse a firmar uno solo para poder probar load_catalog.
    effective_manifest_path = manifest_path if manifest_path is not None else (_MANIFEST_PATH if definitions_dir is None else None)
    if effective_manifest_path is not None and effective_manifest_path.exists():
        manifest = json.loads(effective_manifest_path.read_text(encoding="utf-8"))
        mismatches = verify_integrity_manifest(directory, manifest)
        if mismatches:
            raise CatalogIntegrityError(mismatches)

    catalog: dict[str, ToolDefinition] = {}
    for path in sorted(directory.glob("*.yaml")):
        tool = load_definition(path)
        if tool.name in catalog:
            raise ValueError(f"nombre de herramienta duplicado en el catálogo: {tool.name}")
        catalog[tool.name] = tool
    return catalog


def get_tool(name: str, definitions_dir: pathlib.Path | None = None) -> ToolDefinition:
    catalog = load_catalog(definitions_dir)
    if name not in catalog:
        raise ToolNotFound(name)
    return catalog[name]
