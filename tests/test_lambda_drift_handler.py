"""Tests for AWS Lambda drift handler."""

from src.lambda_drift_handler import lambda_handler


def test_lambda_handler_processes_drift_event():
    event = {
        "account": "123456789012",
        "dry_run": True,
        "detail": {"eventName": "S3_BLOCK_PUBLIC_ACCESS_DRIFT", "recipientAccountId": "123456789012"},
    }
    response = lambda_handler(event, None)
    assert response["statusCode"] == 200
    assert response["body"]["account_id"] == "123456789012"
    assert response["body"]["event_name"] == "S3_BLOCK_PUBLIC_ACCESS_DRIFT"
    assert response["body"]["remediated"] is True
