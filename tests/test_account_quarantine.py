"""Tests for account quarantine and blast-radius isolation."""

from src.core.config import AccountContext, AccountStatus
from src.remediation.account_quarantine import AccountQuarantineController


def test_dry_run_quarantine_account():
    controller = AccountQuarantineController(dry_run=True)
    account = AccountContext(
        account_id="999988887777",
        account_name="Compromised-Sandbox",
        ou_id="ou-sandbox",
        ou_name="Sandbox",
        email="sandbox@company.com",
    )

    success = controller.quarantine_account(account, reason="Active C2 Traffic Detected")
    assert success is True
    assert account.status == AccountStatus.QUARANTINED
    assert account.ou_name == "Quarantine_Lockdown"


def test_dry_run_release_account():
    controller = AccountQuarantineController(dry_run=True)
    account = AccountContext(
        account_id="999988887777",
        account_name="Restored-Account",
        ou_id="ou-quarantine-isolate",
        ou_name="Quarantine_Lockdown",
        email="sandbox@company.com",
        status=AccountStatus.QUARANTINED,
    )

    success = controller.release_account(account, target_ou_id="ou-sandbox", target_ou_name="Sandbox")
    assert success is True
    assert account.status == AccountStatus.COMPLIANT
    assert account.ou_id == "ou-sandbox"
    assert account.ou_name == "Sandbox"
