"""Pytest fixtures and mock AWS credentials for Multi-Account test suite."""

import os
import boto3
import pytest
from moto import mock_aws

os.environ["AWS_ACCESS_KEY_ID"] = "testing-mock-key"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-mock-secret"
os.environ["AWS_SECURITY_TOKEN"] = "testing-mock-token"
os.environ["AWS_SESSION_TOKEN"] = "testing-mock-session"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing-mock-key"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-mock-secret"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def mock_organizations_env(aws_credentials):
    """Provides a mocked AWS Organizations environment."""
    with mock_aws():
        client = boto3.client("organizations", region_name="us-east-1")
        org = client.create_organization(FeatureSet="ALL")["Organization"]
        root_id = client.list_roots()["Roots"][0]["Id"]

        # Create Core, Workloads, and Quarantine OUs
        core_ou = client.create_organizational_unit(ParentId=root_id, Name="Core")["OrganizationalUnit"]
        workloads_ou = client.create_organizational_unit(ParentId=root_id, Name="Workloads")["OrganizationalUnit"]
        quarantine_ou = client.create_organizational_unit(ParentId=root_id, Name="Quarantine_Lockdown")[
            "OrganizationalUnit"
        ]

        yield {
            "client": client,
            "org_id": org["Id"],
            "root_id": root_id,
            "core_ou_id": core_ou["Id"],
            "workloads_ou_id": workloads_ou["Id"],
            "quarantine_ou_id": quarantine_ou["Id"],
        }
