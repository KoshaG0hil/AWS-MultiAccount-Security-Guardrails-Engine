"""Domain configuration and models for multi-account AWS Organization security."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class AccountStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    REMEDIATING = "REMEDIATING"
    QUARANTINED = "QUARANTINED"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AccountContext:
    """Represents an AWS Member Account inside an Organization."""

    account_id: str
    account_name: str
    ou_id: str
    ou_name: str
    email: str
    status: AccountStatus = AccountStatus.COMPLIANT
    active_regions: List[str] = field(default_factory=lambda: ["us-east-1"])
    compliance_score: float = 100.0


@dataclass
class OrganizationalUnit:
    """Represents an AWS Organizational Unit (OU)."""

    ou_id: str
    name: str
    parent_id: str
    attached_scps: List[str] = field(default_factory=list)


@dataclass
class ScpPolicy:
    """Represents a Service Control Policy document."""

    policy_id: str
    name: str
    description: str
    file_path: Path
    raw_json: str
    size_bytes: int


@dataclass
class DriftViolation:
    """A compliance drift violation detected within a member account."""

    violation_id: str
    account_id: str
    rule_name: str
    severity: SeverityLevel
    description: str
    remediation_action: str
    remediated: bool = False
    timestamp: str = ""


@dataclass
class ComplianceScore:
    """Aggregated compliance metrics across all accounts."""

    total_accounts: int
    compliant_accounts: int
    drifted_accounts: int
    quarantined_accounts: int
    overall_percentage: float
    violations_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_accounts": self.total_accounts,
            "compliant_accounts": self.compliant_accounts,
            "drifted_accounts": self.drifted_accounts,
            "quarantined_accounts": self.quarantined_accounts,
            "overall_percentage": self.overall_percentage,
            "violations_count": self.violations_count,
        }


class GovernanceConfig:
    """Encapsulates organizational policies, approved regions, and baseline thresholds."""

    APPROVED_REGIONS: List[str] = ["us-east-1", "us-west-2"]
    MAX_SCP_SIZE_BYTES: int = 5120  # AWS Organizations maximum SCP document size

    @classmethod
    def get_policies_dir(cls, base_dir: Optional[Path] = None) -> Path:
        if base_dir:
            return base_dir / "policies" / "scps"
        return Path(__file__).resolve().parent.parent.parent / "policies" / "scps"
