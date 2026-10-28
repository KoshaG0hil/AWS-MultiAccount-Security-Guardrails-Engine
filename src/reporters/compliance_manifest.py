"""Cryptographic Compliance Manifest and Audit Report Generator."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..core.config import AccountContext, ComplianceScore, DriftViolation


class ComplianceManifestGenerator:
    """Produces tamper-evident JSON and Markdown multi-account compliance audit manifests."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        score: ComplianceScore,
        accounts: List[AccountContext],
        violations: List[DriftViolation],
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()

        accounts_data = [
            {
                "account_id": a.account_id,
                "account_name": a.account_name,
                "ou_name": a.ou_name,
                "status": a.status.value,
                "compliance_score": a.compliance_score,
            }
            for a in accounts
        ]

        violations_data = [
            {
                "violation_id": v.violation_id,
                "account_id": v.account_id,
                "rule_name": v.rule_name,
                "severity": v.severity.value,
                "description": v.description,
                "remediation_action": v.remediation_action,
                "remediated": v.remediated,
            }
            for v in violations
        ]

        report_payload = {
            "platform": "AWS Multi-Account Security Governance & SCP Guardrails Engine",
            "author": "Kosha Gohil",
            "timestamp": timestamp,
            "overall_compliance_percentage": score.overall_percentage,
            "summary": score.to_dict(),
            "accounts": accounts_data,
            "violations": violations_data,
        }

        # Deterministic SHA-256 Checksum Calculation
        canonical_bytes = json.dumps(report_payload, sort_keys=True).encode("utf-8")
        sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()
        report_payload["sha256_checksum"] = sha256_hash

        return report_payload

    def save_report(
        self,
        report_payload: Dict[str, Any],
        filename: str = "sample_compliance_manifest.json",
    ) -> Path:
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)
        return out_path
