from __future__ import annotations

import datetime

import pytest

from policies.approval import (
    ApprovalRejected,
    ApprovalStore,
    compute_plan_hash,
    compute_signature_ref,
)


@pytest.fixture
def plan_hash():
    return compute_plan_hash(tool="isolate_kubernetes_workload", target="deployment/gseg-simulado", action="execute")


@pytest.fixture
def now():
    return datetime.datetime.now(datetime.UTC)


def _approval(approval_id, plan_hash, now, **overrides):
    base = {
        "approval_id": approval_id,
        "approver_id": "soc-1",
        "decision": "APPROVE",
        "expires_at": (now + datetime.timedelta(minutes=5)).isoformat(),
        "signature_ref": compute_signature_ref(approval_id, plan_hash),
    }
    base.update(overrides)
    return base


def test_valid_approval_is_accepted_once(plan_hash, now):
    store = ApprovalStore()
    approval = _approval("appr-1", plan_hash, now)
    store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)


def test_replayed_approval_is_rejected(plan_hash, now):
    store = ApprovalStore()
    approval = _approval("appr-2", plan_hash, now)
    store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)
    with pytest.raises(ApprovalRejected, match="replay"):
        store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)


def test_expired_approval_is_rejected(plan_hash, now):
    store = ApprovalStore()
    expired = _approval("appr-3", plan_hash, now, expires_at=(now - datetime.timedelta(seconds=1)).isoformat())
    with pytest.raises(ApprovalRejected, match="TTL expirado"):
        store.validate_and_consume(expired, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)


def test_tampered_plan_hash_is_rejected(plan_hash, now):
    store = ApprovalStore()
    approval = _approval("appr-4", plan_hash, now)  # firmada para plan_hash original
    different_plan = compute_plan_hash(tool="isolate_kubernetes_workload", target="namespace/production-payments", action="execute")
    with pytest.raises(ApprovalRejected, match="no coincide"):
        store.validate_and_consume(approval, current_plan_hash=different_plan, requester_id="r", executor_id="e", now=now)


def test_self_approval_by_requester_is_rejected(plan_hash, now):
    store = ApprovalStore()
    approval = _approval("appr-5", plan_hash, now, approver_id="langgraph")
    with pytest.raises(ApprovalRejected, match="segregación"):
        store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="langgraph", executor_id="e", now=now)


def test_self_approval_by_executor_is_rejected(plan_hash, now):
    store = ApprovalStore()
    approval = _approval("appr-6", plan_hash, now, approver_id="shuffle-executor")
    with pytest.raises(ApprovalRejected, match="segregación"):
        store.validate_and_consume(approval, current_plan_hash=plan_hash, requester_id="r", executor_id="shuffle-executor", now=now)


def test_rejected_decision_is_never_accepted(plan_hash, now):
    store = ApprovalStore()
    rejected = _approval("appr-7", plan_hash, now, decision="REJECT")
    with pytest.raises(ApprovalRejected, match="REJECT"):
        store.validate_and_consume(rejected, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)


def test_different_approval_ids_do_not_interfere(plan_hash, now):
    store = ApprovalStore()
    a1 = _approval("appr-8a", plan_hash, now)
    a2 = _approval("appr-8b", plan_hash, now)
    store.validate_and_consume(a1, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)
    store.validate_and_consume(a2, current_plan_hash=plan_hash, requester_id="r", executor_id="e", now=now)  # no debe fallar
