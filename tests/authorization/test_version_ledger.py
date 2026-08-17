from __future__ import annotations

import pathlib

import pytest

from tool_catalog import RateLimit, ToolDefinition
from tool_catalog.version_ledger import (
    InvalidLedgerVersion,
    check_for_downgrades,
    load_ledger,
    main,
    write_ledger,
)


def _tool(name: str, version: str) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version=version,
        risk_level="low",
        mode=("read-only",),
        required_scope="cyber.test",
        approval_required=False,
        idempotent=True,
        timeout_seconds=30,
        target_allowlist_required=False,
        rollback_supported=True,
        evidence_required=False,
        side_effect_class="READ_ONLY",
        rate_limit=RateLimit(calls_per_minute=60),
    )


def test_first_time_seen_tool_is_recorded_not_flagged():
    catalog = {"t1": _tool("t1", "1.0.0")}
    result = check_for_downgrades(catalog, ledger={})
    assert result.ok
    assert result.updated_ledger == {"t1": "1.0.0"}


def test_same_or_higher_version_is_not_a_downgrade():
    catalog = {"t1": _tool("t1", "1.2.0")}
    result = check_for_downgrades(catalog, ledger={"t1": "1.1.0"})
    assert result.ok
    assert result.updated_ledger == {"t1": "1.2.0"}


def test_lower_version_than_previously_seen_is_a_downgrade():
    """El caso real que este módulo existe para detectar: alguien sustituye
    isolate_kubernetes_workload.yaml v1.2.0 por una v1.0.0 más permisiva y
    regenera el manifiesto de integridad ANTES de que nadie note nada —
    el hash de tool_catalog/signatures/ coincidiría perfectamente."""
    catalog = {"t1": _tool("t1", "1.0.0")}
    result = check_for_downgrades(catalog, ledger={"t1": "1.2.0"})
    assert not result.ok
    assert "t1" in result.downgrades[0]
    assert "1.0.0" in result.downgrades[0]
    assert "1.2.0" in result.downgrades[0]


def test_downgrade_does_not_lower_the_recorded_high_water_mark():
    catalog = {"t1": _tool("t1", "1.0.0")}
    result = check_for_downgrades(catalog, ledger={"t1": "1.2.0"})
    assert result.updated_ledger["t1"] == "1.2.0"  # no se pisa con la versión inferior


def test_one_tool_downgrading_does_not_block_updating_others():
    catalog = {"t1": _tool("t1", "1.0.0"), "t2": _tool("t2", "2.0.0")}
    result = check_for_downgrades(catalog, ledger={"t1": "1.2.0", "t2": "1.9.0"})
    assert result.downgrades == ("t1: versión actual 1.0.0 < máxima vista 1.2.0",)
    assert result.updated_ledger == {"t1": "1.2.0", "t2": "2.0.0"}


def test_malformed_version_in_ledger_raises_instead_of_comparing_silently():
    catalog = {"t1": _tool("t1", "1.0.0")}
    with pytest.raises(InvalidLedgerVersion):
        check_for_downgrades(catalog, ledger={"t1": "not-a-version"})


def test_write_and_load_ledger_roundtrip(tmp_path: pathlib.Path):
    path = tmp_path / "ledger.json"
    write_ledger({"t1": "1.0.0"}, path)
    assert load_ledger(path) == {"t1": "1.0.0"}


def test_load_ledger_missing_file_returns_empty_dict(tmp_path: pathlib.Path):
    assert load_ledger(tmp_path / "does-not-exist.json") == {}


def test_main_cli_against_the_real_catalog_first_run_is_clean(tmp_path: pathlib.Path, capsys):
    ledger_path = tmp_path / "ledger.json"
    exit_code = main(["check", "--ledger", str(ledger_path), "--update"])
    assert exit_code == 0
    assert "version_ledger OK" in capsys.readouterr().out
    assert ledger_path.exists()

    # Segunda ejecución contra el ledger ya escrito: sigue limpia (mismas versiones).
    exit_code_again = main(["check", "--ledger", str(ledger_path)])
    assert exit_code_again == 0


def test_main_cli_detects_a_downgrade_and_does_not_persist_it(tmp_path: pathlib.Path, capsys):
    ledger_path = tmp_path / "ledger.json"
    write_ledger({"isolate_kubernetes_workload": "99.0.0"}, ledger_path)  # versión futura fabricada

    exit_code = main(["check", "--ledger", str(ledger_path), "--update"])
    assert exit_code == 1
    assert "DOWNGRADE" in capsys.readouterr().out
    assert load_ledger(ledger_path) == {"isolate_kubernetes_workload": "99.0.0"}  # no se sobrescribió
