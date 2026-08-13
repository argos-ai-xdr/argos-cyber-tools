from __future__ import annotations

import pathlib

import pytest

from executors import ContractsRepoNotFound, resolve_contracts_path


@pytest.fixture(scope="session")
def contracts_path() -> pathlib.Path:
    try:
        return resolve_contracts_path()
    except ContractsRepoNotFound as exc:
        pytest.skip(str(exc))
