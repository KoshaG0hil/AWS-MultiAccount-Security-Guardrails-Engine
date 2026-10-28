"""Tests for compliance manifest generation and SHA-256 integrity."""

from pathlib import Path
from src.core.config import AccountContext, ComplianceScore, DriftViolation, SeverityLevel
from src.reporters.compliance_manifest import ComplianceManifestGenerator


def test_manifest_generation_and_integrity(tmp_path: Path):
    generator = ComplianceManifestGenerator(output_dir=tmp_path)
    score = ComplianceScore(
        total_accounts=2,
        compliant_accounts=1,
        drifted_accounts=1,
        quarantined_accounts=0,
        overall_percentage=85.0,
        violations_count=1,
    )
    accounts = [
        AccountContext("1111", "Prod", "ou-prod", "Production", "prod@co.com"),
        AccountContext("2222", "Dev", "ou-dev", "Development", "dev@co.com"),
    ]
    violations = [
        DriftViolation(
            "VIO-1", "2222", "S3_BLOCK_PUBLIC_ACCESS_DRIFT", SeverityLevel.HIGH, "S3 drift", "Re-enable", True
        )
    ]

    manifest = generator.generate(score, accounts, violations)
    assert "sha256_checksum" in manifest
    assert len(manifest["sha256_checksum"]) == 64

    # Save to file
    out_file = generator.save_report(manifest, filename="test_manifest.json")
    assert out_file.exists()
    assert out_file.stat().st_size > 0
