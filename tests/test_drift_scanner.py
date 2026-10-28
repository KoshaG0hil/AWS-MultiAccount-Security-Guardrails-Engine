"""Tests for Multi-Account Drift Detection Scanner."""

from src.core.config import AccountContext, AccountStatus
from src.scanners.drift_scanner import MultiAccountDriftScanner


def test_clean_account_has_no_violations():
    scanner = MultiAccountDriftScanner()
    account = AccountContext(
        account_id="111122223333",
        account_name="Prod-App-01",
        ou_id="ou-prod",
        ou_name="Production",
        email="prod@company.com",
    )
    violations = scanner.scan_account(account, simulated_drift={})
    assert len(violations) == 0


def test_detects_multiple_drift_violations():
    scanner = MultiAccountDriftScanner()
    account = AccountContext(
        account_id="444455556666",
        account_name="Staging-App",
        ou_id="ou-nonprod",
        ou_name="NonProduction",
        email="dev@company.com",
    )
    drift_payload = {
        "s3_public_access_disabled": True,
        "has_unapproved_regions": True,
        "rogue_region": "eu-west-1",
        "rogue_igw_attached": True,
        "root_account_active": True,
    }
    violations = scanner.scan_account(account, simulated_drift=drift_payload)
    assert len(violations) == 4
    rule_names = [v.rule_name for v in violations]
    assert "S3_BLOCK_PUBLIC_ACCESS_DRIFT" in rule_names
    assert "CIS_DISALLOWED_REGION_USAGE" in rule_names
    assert "NETWORK_UNAUTHORIZED_IGW_ATTACHMENT" in rule_names
    assert "CIS_ROOT_USER_ACTIVITY" in rule_names


def test_calculate_compliance_score():
    scanner = MultiAccountDriftScanner()
    accounts = [
        AccountContext("1111", "Acc1", "ou1", "OU1", "a1@test.com"),
        AccountContext("2222", "Acc2", "ou1", "OU1", "a2@test.com"),
        AccountContext("3333", "Acc3", "ou2", "OU2", "a3@test.com", status=AccountStatus.QUARANTINED),
    ]
    # Acc1 has 1 violation, Acc2 has 0 violations, Acc3 is quarantined
    violations_by_account = {
        "1111": [scanner.scan_account(accounts[0], simulated_drift={"s3_public_access_disabled": True})[0]],
        "2222": [],
        "3333": [],
    }

    score = scanner.calculate_compliance(accounts, violations_by_account)
    assert score.total_accounts == 3
    assert score.compliant_accounts == 1
    assert score.drifted_accounts == 1
    assert score.quarantined_accounts == 1
    assert 0.0 <= score.overall_percentage <= 100.0
