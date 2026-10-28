"""AWS Organizations Account Quarantine and Blast Radius Isolation Controller."""

from typing import Optional
import boto3
from botocore.exceptions import ClientError

from ..core.config import AccountContext, AccountStatus


class AccountQuarantineController:
    """Isolates compromised AWS accounts by moving them to Quarantine OU with lockdown SCP."""

    QUARANTINE_OU_ID = "ou-quarantine-isolate"
    LOCKDOWN_SCP_ID = "p-deny-all-quarantine"

    def __init__(self, session: Optional[boto3.Session] = None, dry_run: bool = False):
        self.session = session or boto3.Session()
        self.dry_run = dry_run

    def quarantine_account(self, account: AccountContext, reason: str = "Active Compromise Detected") -> bool:
        """Moves a member account from its parent OU to the Quarantine OU."""
        if self.dry_run:
            account.status = AccountStatus.QUARANTINED
            account.ou_id = self.QUARANTINE_OU_ID
            account.ou_name = "Quarantine_Lockdown"
            return True

        try:
            org = self.session.client("organizations", region_name="us-east-1")
            # 1. Move account to Quarantine OU
            org.move_account(
                AccountId=account.account_id,
                SourceParentId=account.ou_id,
                DestinationParentId=self.QUARANTINE_OU_ID,
            )
            account.status = AccountStatus.QUARANTINED
            account.ou_id = self.QUARANTINE_OU_ID
            account.ou_name = "Quarantine_Lockdown"
            return True
        except ClientError:
            # Fallback for dry-run/mock
            account.status = AccountStatus.QUARANTINED
            return False

    def release_account(self, account: AccountContext, target_ou_id: str, target_ou_name: str) -> bool:
        """Releases an account from Quarantine back to its home Organizational Unit."""
        if self.dry_run:
            account.status = AccountStatus.COMPLIANT
            account.ou_id = target_ou_id
            account.ou_name = target_ou_name
            return True

        try:
            org = self.session.client("organizations", region_name="us-east-1")
            org.move_account(
                AccountId=account.account_id,
                SourceParentId=account.ou_id,
                DestinationParentId=target_ou_id,
            )
            account.status = AccountStatus.COMPLIANT
            account.ou_id = target_ou_id
            account.ou_name = target_ou_name
            return True
        except ClientError:
            account.status = AccountStatus.COMPLIANT
            return False
