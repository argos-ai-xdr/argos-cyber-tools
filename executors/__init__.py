"""Helpers compartidos por todos los executors: resolución de
argos-contracts-scenarios, construcción del envelope y un almacén de
idempotencia real (no un comentario diciendo "esto es idempotente" — un
reintento con la misma idempotency_key devuelve el ActionResult ya
producido, sin repetir el efecto).

Duplicado deliberadamente respecto a argos-core/libs/argos_envelope y
argos-core/libs/argos_testing: son repositorios distintos, sin dependencia
de paquete entre sí (cada uno se instala y despliega por separado); el
patrón es el mismo a propósito, no un descuido.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import uuid

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS_ENV_VAR = "ARGOS_CONTRACTS_PATH"


class ContractsRepoNotFound(RuntimeError):
    pass


def resolve_contracts_path(start: pathlib.Path | None = None) -> pathlib.Path:
    env_value = os.environ.get(CONTRACTS_ENV_VAR)
    if env_value:
        path = pathlib.Path(env_value).expanduser().resolve()
        if not path.exists():
            raise ContractsRepoNotFound(f"{CONTRACTS_ENV_VAR}={env_value!r} no existe")
        return path

    base = start or pathlib.Path(__file__).resolve().parent.parent
    sibling = (base.parent / "argos-contracts-scenarios").resolve()
    if sibling.exists():
        return sibling

    raise ContractsRepoNotFound(
        "No se encontró argos-contracts-scenarios. Clónalo como hermano de "
        f"este repositorio o define {CONTRACTS_ENV_VAR}."
    )


def build_registry(contracts_path: pathlib.Path) -> Registry:
    schemas_dir = contracts_path / "schemas"
    envelope_path = contracts_path / "envelope" / "v1" / "argos-envelope.schema.json"
    resources = []
    for path in list(schemas_dir.rglob("*.schema.json")) + [envelope_path]:
        data = json.loads(path.read_text(encoding="utf-8"))
        resources.append((path.as_uri(), Resource.from_contents(data)))
    return Registry().with_resources(resources)


def validate_payload(contracts_path: pathlib.Path, registry: Registry, contract: str, payload: dict) -> list[str]:
    schema_path = contracts_path / "schemas" / contract / "v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema = {**schema, "$id": schema_path.as_uri()}
    validator = Draft202012Validator(schema, registry=registry)
    return [e.message for e in validator.iter_errors(payload)]


def new_id_prefixed(prefix: str) -> str:
    if not (1 <= len(prefix) <= 15):
        raise ValueError("prefix debe tener entre 1 y 15 caracteres")
    hex_len = 36 - len(prefix) - 1
    return f"{prefix}-{uuid.uuid4().hex[:hex_len]}"


def sha256_of_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_envelope(payload: dict, *, producer: str, run_id: str, message_id: str) -> dict:
    return {
        "id": message_id,
        "schema_version": "1.0.0",
        "observed_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "producer": producer,
        "classification": "internal",
        "run_id": run_id,
        "payload_hash": sha256_of_payload(payload),
    }


class InvalidActionResult(Exception):
    def __init__(self, errors: list[str]):
        super().__init__(f"ActionResult inválido: {errors}")
        self.errors = errors


@dataclasses.dataclass
class IdempotencyStore:
    """Real: un reintento con la misma idempotency_key devuelve el
    ActionResult ya producido en vez de reejecutar el efecto (AC13,
    ADR-002)."""

    _results: dict[str, dict] = dataclasses.field(default_factory=dict)

    def get(self, idempotency_key: str) -> dict | None:
        return self._results.get(idempotency_key)

    def remember(self, idempotency_key: str, action_result: dict) -> None:
        self._results[idempotency_key] = action_result
