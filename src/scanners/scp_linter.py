"""SCP Policy Linter and Structural Validation Engine."""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import List
from ..core.config import GovernanceConfig


@dataclass
class ScpLintResult:
    policy_name: str
    file_path: str
    size_bytes: int
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ScpLinter:
    """Validates AWS Service Control Policies against official limits and best practices."""

    MAX_BYTES = GovernanceConfig.MAX_SCP_SIZE_BYTES

    def lint_file(self, file_path: Path) -> ScpLintResult:
        policy_name = file_path.stem
        errors: List[str] = []
        warnings: List[str] = []

        if not file_path.exists():
            return ScpLintResult(
                policy_name=policy_name,
                file_path=str(file_path),
                size_bytes=0,
                is_valid=False,
                errors=["File not found"],
            )

        raw_content = file_path.read_text(encoding="utf-8")
        size_bytes = len(raw_content.encode("utf-8"))

        # 1. Size Limit Check (AWS 5,120 bytes max)
        if size_bytes > self.MAX_BYTES:
            errors.append(
                f"Policy size ({size_bytes} bytes) exceeds AWS Organizations 5,120-byte limit by {size_bytes - self.MAX_BYTES} bytes"
            )

        # 2. JSON Syntax Validation
        try:
            doc = json.loads(raw_content)
        except json.JSONDecodeError as err:
            errors.append(f"Invalid JSON syntax: {err}")
            return ScpLintResult(
                policy_name=policy_name,
                file_path=str(file_path),
                size_bytes=size_bytes,
                is_valid=False,
                errors=errors,
            )

        # 3. Structure & Statements Verification
        version = doc.get("Version")
        if version != "2012-10-17":
            warnings.append(f"Version is '{version}'; recommended is '2012-10-17'")

        statements = doc.get("Statement", [])
        if not statements or not isinstance(statements, list):
            errors.append("Policy must contain a non-empty 'Statement' array")
            return ScpLintResult(
                policy_name=policy_name,
                file_path=str(file_path),
                size_bytes=size_bytes,
                is_valid=False,
                errors=errors,
                warnings=warnings,
            )

        for idx, stmt in enumerate(statements):
            sid = stmt.get("Sid", f"Statement[{idx}]")
            effect = stmt.get("Effect")
            if effect not in ["Allow", "Deny"]:
                errors.append(f"{sid}: Effect must be 'Allow' or 'Deny', got '{effect}'")

            action = stmt.get("Action")
            not_action = stmt.get("NotAction")
            if not action and not not_action:
                errors.append(f"{sid}: Statement must define 'Action' or 'NotAction'")

            # Warn on unrestricted Wildcard Action: "*" without Conditions
            if action == "*" and effect == "Deny" and not stmt.get("Condition"):
                warnings.append(f"{sid}: Deny-All without Condition block can lock out entire member account access")

        is_valid = len(errors) == 0
        return ScpLintResult(
            policy_name=policy_name,
            file_path=str(file_path),
            size_bytes=size_bytes,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
        )

    def lint_directory(self, dir_path: Path) -> List[ScpLintResult]:
        results: List[ScpLintResult] = []
        if not dir_path.exists():
            return results
        for json_file in sorted(dir_path.glob("*.json")):
            results.append(self.lint_file(json_file))
        return results
