"""Version Downgrade detection (ADR-019, SECURE TOOL LIFECYCLE).

`tool_catalog/signatures/` ya detecta si un archivo de definición cambió
desde que se firmó el manifiesto (hash SHA-256). Eso NO detecta un
downgrade: si un atacante (o un error de despliegue) sustituye
`isolate_kubernetes_workload.yaml` v1.2.0 por una v1.0.0 más permisiva
ANTES de regenerar `catalog.manifest.json`, el hash del manifiesto
regenerado coincidirá perfectamente con el archivo antiguo — íntegro,
pero desactualizado hacia atrás.

Este ledger es append-only: registra la versión más alta vista por
`tool_id` y marca como downgrade cualquier carga posterior con una
versión menor para el mismo nombre, incluso si su integridad de archivo
es intachable.

Deliberadamente NO se invoca desde `load_catalog()` por defecto: a
diferencia de la verificación de hash (que protege cada arranque del
gateway), este ledger requiere una ubicación persistente entre
ejecuciones (no solo dentro de un proceso) que hoy no está resuelta —
usarlo hoy es una comprobación explícita en CI/despliegue
(`python -m tool_catalog.version_ledger check --ledger <path>`), no un
efecto colateral silencioso de cargar el catálogo.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib

from tool_catalog import ToolDefinition


class InvalidLedgerVersion(ValueError):
    pass


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise InvalidLedgerVersion(f"versión no es MAJOR.MINOR.PATCH: {version!r}")
    major, minor, patch = parts
    return (int(major), int(minor), int(patch))


def load_ledger(path: pathlib.Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_ledger(ledger: dict[str, str], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@dataclasses.dataclass(frozen=True)
class VersionCheckResult:
    downgrades: tuple[str, ...]
    updated_ledger: dict[str, str]

    @property
    def ok(self) -> bool:
        return not self.downgrades


def check_for_downgrades(catalog: dict[str, ToolDefinition], ledger: dict[str, str]) -> VersionCheckResult:
    """No muta `ledger` -- devuelve `updated_ledger` para que el llamante
    decida si persistirlo (solo tiene sentido persistir tras una
    comprobación limpia; no se sube el high-water mark con la MISMA
    llamada que detecta un downgrade de otro tool en el mismo catálogo)."""
    downgrades: list[str] = []
    updated = dict(ledger)
    for name, tool in catalog.items():
        recorded = updated.get(name)
        if recorded is None:
            updated[name] = tool.version
            continue
        if _version_tuple(tool.version) < _version_tuple(recorded):
            downgrades.append(f"{name}: versión actual {tool.version} < máxima vista {recorded}")
            continue
        if _version_tuple(tool.version) > _version_tuple(recorded):
            updated[name] = tool.version
    return VersionCheckResult(downgrades=tuple(downgrades), updated_ledger=updated)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from tool_catalog import load_catalog

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check"])
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--definitions-dir", type=pathlib.Path, default=None)
    parser.add_argument(
        "--update",
        action="store_true",
        help="Si la comprobación es limpia, persiste el ledger actualizado (high-water mark). Nunca se persiste si hay downgrades.",
    )
    args = parser.parse_args(argv)

    catalog = load_catalog(args.definitions_dir)
    ledger = load_ledger(args.ledger)
    result = check_for_downgrades(catalog, ledger)

    for downgrade in result.downgrades:
        print(f"DOWNGRADE: {downgrade}")

    if result.ok:
        if args.update:
            write_ledger(result.updated_ledger, args.ledger)
        print("version_ledger OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
