resource "aws_organizations_organization" "org" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "sso.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com"
  ]

  feature_set = var.org_feature_set

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY"
  ]
}

# Core Organizational Unit (Security, Logging, Shared Services)
resource "aws_organizations_organizational_unit" "core" {
  name      = "Core"
  parent_id = aws_organizations_organization.org.roots[0].id

  tags = merge(local.common_tags, {
    OU_Type = "Infrastructure-Core"
  })
}

# Production Workloads Organizational Unit
resource "aws_organizations_organizational_unit" "workloads_prod" {
  name      = "Workloads_Prod"
  parent_id = aws_organizations_organization.org.roots[0].id

  tags = merge(local.common_tags, {
    OU_Type = "Production-Workloads"
  })
}

# Non-Production Workloads Organizational Unit
resource "aws_organizations_organizational_unit" "workloads_nonprod" {
  name      = "Workloads_NonProd"
  parent_id = aws_organizations_organization.org.roots[0].id

  tags = merge(local.common_tags, {
    OU_Type = "NonProduction-Development"
  })
}

# Quarantine Containment Organizational Unit
resource "aws_organizations_organizational_unit" "quarantine" {
  name      = var.quarantine_ou_name
  parent_id = aws_organizations_organization.org.roots[0].id

  tags = merge(local.common_tags, {
    OU_Type = "Security-Containment"
    Status  = "Restricted"
  })
}
