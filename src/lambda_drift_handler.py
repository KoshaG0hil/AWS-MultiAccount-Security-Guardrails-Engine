"""AWS Lambda Handler for Multi-Account Drift Remediation and EventBridge Triggers."""

from typing import Any, Dict
from .core.config import DriftViolation, SeverityLevel
from .remediation.self_healing_enforcer import SelfHealingEnforcer


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entrypoint triggered by AWS Config or EventBridge multi-account drift events."""
    try:
        dry_run = event.get("dry_run", False)
        enforcer = SelfHealingEnforcer(dry_run=dry_run)
        detail = event.get("detail", {})
        account_id = event.get("account") or detail.get("recipientAccountId", "111122223333")
        event_name = detail.get("eventName", "SimulatedDriftEvent")

        # Map Event to DriftViolation
        violation = DriftViolation(
            violation_id=f"VIO-LAMBDA-{account_id}",
            account_id=account_id,
            rule_name=event_name,
            severity=SeverityLevel.HIGH,
            description=f"Automated event trigger from {event_name}",
            remediation_action="Triggered automated self-healing action",
        )

        success = enforcer.remediate_violation(violation)

        return {
            "statusCode": 200,
            "body": {
                "account_id": account_id,
                "event_name": event_name,
                "remediated": success,
            },
        }
    except Exception as exc:
        return {
            "statusCode": 500,
            "error": str(exc),
        }
