"""Multi-Account Landing Zone Drift Detection Scanner."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

from ..core.config import (
    AccountContext,
    AccountStatus,
    ComplianceScore,
    DriftViolation,
    SeverityLevel,
)


class MultiAccountDriftScanner:
    """Scans member accounts across Organizational Units for security baseline drift."""

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()

    def scan_account(
        self, account: AccountContext, simulated_drift: Optional[Dict[str, Any]] = None
    ) -> List[DriftViolation]:
        """Scans a member account for compliance drift across security pillars."""
        violations: List[DriftViolation] = []
        now = datetime.now(timezone.utc).isoformat()

        # If simulated_drift payload is supplied, use it (for deterministic demo/unit tests)
        if simulated_drift is not None:
            if simulated_drift.get("has_unapproved_regions"):
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-01",
                        account_id=account.account_id,
                        rule_name="CIS_DISALLOWED_REGION_USAGE",
                        severity=SeverityLevel.HIGH,
                        description=f"EC2 compute resource spawned in unapproved region ({simulated_drift.get('rogue_region', 'eu-west-1')})",
                        remediation_action="Terminate rogue region resources and enforce Region SCP",
                        timestamp=now,
                    )
                )

            if simulated_drift.get("root_account_active"):
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-02",
                        account_id=account.account_id,
                        rule_name="CIS_ROOT_USER_ACTIVITY",
                        severity=SeverityLevel.CRITICAL,
                        description="Root account console login or access key generation detected",
                        remediation_action="Revoke root access keys and lock down root credentials",
                        timestamp=now,
                    )
                )

            if simulated_drift.get("s3_public_access_disabled"):
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-03",
                        account_id=account.account_id,
                        rule_name="S3_BLOCK_PUBLIC_ACCESS_DRIFT",
                        severity=SeverityLevel.CRITICAL,
                        description="Account-level S3 Block Public Access setting was disabled",
                        remediation_action="Re-enable S3 Account-Level Public Access Block",
                        timestamp=now,
                    )
                )

            if simulated_drift.get("rogue_igw_attached"):
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-04",
                        account_id=account.account_id,
                        rule_name="NETWORK_UNAUTHORIZED_IGW_ATTACHMENT",
                        severity=SeverityLevel.HIGH,
                        description=f"Unauthorized Internet Gateway {simulated_drift.get('igw_id', 'igw-0987654321')} attached to VPC",
                        remediation_action="Detach unauthorized Internet Gateway to eliminate public egress",
                        timestamp=now,
                    )
                )

            if simulated_drift.get("cloudtrail_logging_stopped"):
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-05",
                        account_id=account.account_id,
                        rule_name="CIS_CLOUDTRAIL_AUDIT_DISABLED",
                        severity=SeverityLevel.CRITICAL,
                        description="Organization central CloudTrail multi-region logging was disabled",
                        remediation_action="Restart CloudTrail trail recorder immediately",
                        timestamp=now,
                    )
                )

            return violations

        # Live boto3 scanning against active member account
        try:
            s3_client = self.session.client("s3control", region_name="us-east-1")
            try:
                res = s3_client.get_public_access_block(AccountId=account.account_id)
                pab = res.get("PublicAccessBlockConfiguration", {})
                if not all(
                    [
                        pab.get("BlockPublicAcls"),
                        pab.get("IgnorePublicAcls"),
                        pab.get("BlockPublicPolicy"),
                        pab.get("RestrictPublicBuckets"),
                    ]
                ):
                    violations.append(
                        DriftViolation(
                            violation_id=f"VIO-{account.account_id}-03",
                            account_id=account.account_id,
                            rule_name="S3_BLOCK_PUBLIC_ACCESS_DRIFT",
                            severity=SeverityLevel.CRITICAL,
                            description="Account-level S3 Block Public Access is partially or completely disabled",
                            remediation_action="Re-enable S3 Account-Level Public Access Block",
                            timestamp=now,
                        )
                    )
            except ClientError:
                # If cannot read or not set, flag as drift
                violations.append(
                    DriftViolation(
                        violation_id=f"VIO-{account.account_id}-03",
                        account_id=account.account_id,
                        rule_name="S3_BLOCK_PUBLIC_ACCESS_DRIFT",
                        severity=SeverityLevel.CRITICAL,
                        description="No S3 Account-Level Public Access Block configuration present",
                        remediation_action="Enforce S3 Account-Level Public Access Block",
                        timestamp=now,
                    )
                )
        except Exception:
            pass

        return violations

    def calculate_compliance(
        self,
        accounts: List[AccountContext],
        violations_by_account: Dict[str, List[DriftViolation]],
    ) -> ComplianceScore:
        """Calculates aggregated organizational compliance metrics."""
        total = len(accounts)
        if total == 0:
            return ComplianceScore(0, 0, 0, 0, 100.0, 0)

        quarantined = sum(1 for a in accounts if a.status == AccountStatus.QUARANTINED)
        total_violations = sum(len(v) for v in violations_by_account.values())

        drifted = sum(1 for a in accounts if len(violations_by_account.get(a.account_id, [])) > 0)
        compliant = total - drifted - quarantined

        # Weighted calculation (each violation deducts proportional points)
        max_possible_points = total * 100
        penalty = min(max_possible_points, total_violations * 15)
        overall_pct = round(((max_possible_points - penalty) / max_possible_points) * 100.0, 1)

        return ComplianceScore(
            total_accounts=total,
            compliant_accounts=compliant,
            drifted_accounts=drifted,
            quarantined_accounts=quarantined,
            overall_percentage=max(0.0, overall_pct),
            violations_count=total_violations,
        )
