"""Integridad del catálogo. Hoy: hash SHA-256 real de cada definición
(detecta modificación no autorizada de un archivo ya "congelado"). Firma
criptográfica real (Cosign, mismo mecanismo que las imágenes de contenedor,
ADR-013) pendiente de ARG-002 — un hash sin firma no prueba *quién* lo
generó, solo que no cambió desde que se generó el manifiesto.
"""
from __future__ import annotations

import hashlib
import json
import pathlib


def hash_definition(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_integrity_manifest(definitions_dir: pathlib.Path) -> dict:
    return {
        path.stem: hash_definition(path)
        for path in sorted(definitions_dir.glob("*.yaml"))
    }


def verify_integrity_manifest(definitions_dir: pathlib.Path, manifest: dict) -> list[str]:
    """Devuelve la lista de discrepancias (vacía si todo coincide): archivo
    modificado, archivo nuevo sin entrada en el manifiesto, o entrada del
    manifiesto sin archivo correspondiente."""
    current = build_integrity_manifest(definitions_dir)
    mismatches = []
    for name, expected_hash in manifest.items():
        if name not in current:
            mismatches.append(f"{name}: en el manifiesto pero el archivo no existe")
        elif current[name] != expected_hash:
            mismatches.append(f"{name}: hash no coincide (modificado tras firmar el manifiesto)")
    for name in current:
        if name not in manifest:
            mismatches.append(f"{name}: archivo nuevo sin entrada en el manifiesto")
    return mismatches


def write_integrity_manifest(definitions_dir: pathlib.Path, out_path: pathlib.Path) -> None:
    manifest = build_integrity_manifest(definitions_dir)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
