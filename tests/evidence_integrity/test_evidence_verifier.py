from __future__ import annotations

import hashlib

import pytest

from executors.evidence_verifier import RemoteEvidenceClient, verify_artifact_integrity


def test_matching_content_and_hash_verifies():
    content = b"real artifact bytes, not a placeholder"
    expected = hashlib.sha256(content).hexdigest()
    assert verify_artifact_integrity(content, expected) is True


def test_tampered_content_fails_verification():
    content = b"real artifact bytes, not a placeholder"
    expected = hashlib.sha256(content).hexdigest()
    tampered = b"real artifact bytes, not a placeholder!"  # un byte de más
    assert verify_artifact_integrity(tampered, expected) is False


def test_empty_content_is_not_confused_with_missing_hash():
    """No debe tratarse b'' como un caso especial 'sin contenido, pasa
    igual' — su hash real es un valor fijo conocido y debe compararse
    igual que cualquier otro."""
    empty_hash = hashlib.sha256(b"").hexdigest()
    assert verify_artifact_integrity(b"", empty_hash) is True
    assert verify_artifact_integrity(b"", "0" * 64) is False


def test_remote_evidence_client_is_not_implemented_yet():
    with pytest.raises(NotImplementedError):
        RemoteEvidenceClient("http://evidence.local").fetch_artifact("art-1")
