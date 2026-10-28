"""Tests for Service Control Policy (SCP) linter."""

import json
from pathlib import Path
from src.scanners.scp_linter import ScpLinter


def test_lint_valid_policy_file(tmp_path: Path):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnapprovedRegions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}},
            }
        ],
    }
    file = tmp_path / "test_policy.json"
    file.write_text(json.dumps(policy_doc), encoding="utf-8")

    linter = ScpLinter()
    result = linter.lint_file(file)

    assert result.is_valid is True
    assert len(result.errors) == 0
    assert result.size_bytes < 5120


def test_lint_oversized_policy_fails(tmp_path: Path):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "LargeStatement", "Effect": "Deny", "Action": ["ec2:" + "x" * 5000], "Resource": "*"}],
    }
    file = tmp_path / "oversized_policy.json"
    file.write_text(json.dumps(policy_doc), encoding="utf-8")

    linter = ScpLinter()
    result = linter.lint_file(file)

    assert result.is_valid is False
    assert any("exceeds AWS Organizations 5,120-byte limit" in err for err in result.errors)


def test_lint_invalid_json_syntax(tmp_path: Path):
    file = tmp_path / "invalid_syntax.json"
    file.write_text("{ unclosed json: true, ", encoding="utf-8")

    linter = ScpLinter()
    result = linter.lint_file(file)

    assert result.is_valid is False
    assert any("Invalid JSON syntax" in err for err in result.errors)


def test_lint_all_actual_scps():
    """Validates all real project SCPs in policies/scps directory."""
    linter = ScpLinter()
    policies_dir = Path(__file__).resolve().parent.parent / "policies" / "scps"

    results = linter.lint_directory(policies_dir)
    assert len(results) >= 5
    for res in results:
        assert res.is_valid is True, f"Policy {res.policy_name} failed linting: {res.errors}"
        assert res.size_bytes <= 5120
