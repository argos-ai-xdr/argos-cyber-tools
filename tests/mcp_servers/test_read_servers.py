from __future__ import annotations

from mcp_servers.assets import InMemoryAssetServer
from mcp_servers.vulnerabilities import InMemoryVulnerabilityServer

_ASSETS = [
    {"asset_id": "a1", "namespace": "argos-cyber-range"},
    {"asset_id": "a2", "namespace": "argos-xdr"},
]

_FINDINGS = [
    {"finding_id": "f1", "asset_id": "a1", "cve_id": "CVE-2024-1"},
    {"finding_id": "f2", "asset_id": "a2", "cve_id": "CVE-2024-2"},
]


def test_asset_server_lists_everything_without_a_namespace_filter():
    server = InMemoryAssetServer(assets=_ASSETS)
    assert server.list_assets() == _ASSETS


def test_asset_server_filters_by_namespace():
    server = InMemoryAssetServer(assets=_ASSETS)
    result = server.list_assets(namespace="argos-cyber-range")
    assert result == [_ASSETS[0]]


def test_asset_server_never_fabricates_data_for_an_empty_namespace():
    server = InMemoryAssetServer(assets=_ASSETS)
    assert server.list_assets(namespace="does-not-exist") == []


def test_asset_server_with_no_assets_loaded_returns_empty_not_an_error():
    server = InMemoryAssetServer()
    assert server.list_assets() == []


def test_vulnerability_server_lists_everything_without_an_asset_filter():
    server = InMemoryVulnerabilityServer(findings=_FINDINGS)
    assert server.list_findings() == _FINDINGS


def test_vulnerability_server_filters_by_asset_id():
    server = InMemoryVulnerabilityServer(findings=_FINDINGS)
    result = server.list_findings(asset_id="a2")
    assert result == [_FINDINGS[1]]


def test_vulnerability_server_with_no_findings_loaded_returns_empty_not_an_error():
    server = InMemoryVulnerabilityServer()
    assert server.list_findings() == []
