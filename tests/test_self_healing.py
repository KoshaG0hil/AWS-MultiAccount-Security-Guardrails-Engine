"""Tests for automated self-healing drift remediation."""

from src.core.config import DriftViolation, SeverityLevel
from src.remediation.self_healing_enforcer import SelfHealingEnforcer


def test_dry_run_remediation():
    enforcer = SelfHealingEnforcer(dry_run=True)
    violation = DriftViolation(
        violation_id="VIO-TEST-01",
        account_id="111122223333",
        rule_name="S3_BLOCK_PUBLIC_ACCESS_DRIFT",
        severity=SeverityLevel.CRITICAL,
        description="Public access block disabled",
        remediation_action="Re-enable Public Access Block",
        remediated=False,
    )
    success = enforcer.remediate_violation(violation)
    assert success is True
    assert violation.remediated is True


def test_remediate_all_violations():
    enforcer = SelfHealingEnforcer(dry_run=True)
    violations = [
        DriftViolation("VIO-1", "1111", "S3_BLOCK_PUBLIC_ACCESS_DRIFT", SeverityLevel.CRITICAL, "d1", "r1"),
        DriftViolation("VIO-2", "2222", "NETWORK_UNAUTHORIZED_IGW_ATTACHMENT", SeverityLevel.HIGH, "d2", "r2"),
        DriftViolation("VIO-3", "3333", "CIS_CLOUDTRAIL_AUDIT_DISABLED", SeverityLevel.CRITICAL, "d3", "r3"),
    ]
    remediated_count = enforcer.remediate_all(violations)
    assert remediated_count == 3
    assert all(v.remediated is True for v in violations)
