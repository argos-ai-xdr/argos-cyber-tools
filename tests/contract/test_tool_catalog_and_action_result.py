from __future__ import annotations

import pytest

from executors.kubernetes import KubernetesExecutor
from tool_catalog import InvalidToolDefinition, load_catalog
from tool_catalog.signatures import build_integrity_manifest, verify_integrity_manifest


def test_full_catalog_loads_and_validates():
    catalog = load_catalog()
    assert len(catalog) == 5
    assert catalog["isolate_kubernetes_workload"].risk_level == "high"


def test_high_risk_tools_always_require_approval_and_allowlist():
    catalog = load_catalog()
    for tool in catalog.values():
        if tool.risk_level in ("high", "critical"):
            assert tool.approval_required is True
            assert tool.target_allowlist_required is True


def test_execute_mode_tools_always_require_evidence():
    catalog = load_catalog()
    for tool in catalog.values():
        if "execute" in tool.mode:
            assert tool.evidence_required is True


def test_invalid_definition_is_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad_tool\nversion: 1.0.0\nrisk_level: high\n", encoding="utf-8")  # faltan campos obligatorios
    from tool_catalog import load_definition

    with pytest.raises(InvalidToolDefinition):
        load_definition(bad)


def test_integrity_manifest_detects_tampering(tmp_path):
    definitions_dir = tmp_path / "definitions"
    definitions_dir.mkdir()
    (definitions_dir / "t1.yaml").write_text("a: 1\n", encoding="utf-8")
    manifest = build_integrity_manifest(definitions_dir)

    assert verify_integrity_manifest(definitions_dir, manifest) == []

    (definitions_dir / "t1.yaml").write_text("a: 2\n", encoding="utf-8")  # modificado tras firmar
    mismatches = verify_integrity_manifest(definitions_dir, manifest)
    assert len(mismatches) == 1
    assert "no coincide" in mismatches[0]


def test_kubernetes_executor_action_result_validates_against_real_schema(contracts_path):
    executor = KubernetesExecutor(contracts_path)
    result = executor.isolate_workload(
        run_id="run-contract-1", target="deployment/x", dry_run=True, idempotency_key="k-contract-1", action_id="pol-1"
    )
    assert result["dry_run"] is True
