# Root Level Attachments (Inherited by all accounts in the organization)
resource "aws_organizations_policy_attachment" "root_region_restriction" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_policy_attachment" "root_user_denial" {
  policy_id = aws_organizations_policy.root_user_denial.id
  target_id = aws_organizations_organization.org.roots[0].id
}

# Production Workloads Attachments
resource "aws_organizations_policy_attachment" "prod_security_services" {
  policy_id = aws_organizations_policy.security_services_protection.id
  target_id = aws_organizations_organizational_unit.workloads_prod.id
}

resource "aws_organizations_policy_attachment" "prod_network_perimeter" {
  policy_id = aws_organizations_policy.network_perimeter_guardrails.id
  target_id = aws_organizations_organizational_unit.workloads_prod.id
}

resource "aws_organizations_policy_attachment" "prod_s3_ransomware" {
  policy_id = aws_organizations_policy.s3_ransomware_protection.id
  target_id = aws_organizations_organizational_unit.workloads_prod.id
}

# Non-Production Workloads Attachments
resource "aws_organizations_policy_attachment" "nonprod_security_services" {
  policy_id = aws_organizations_policy.security_services_protection.id
  target_id = aws_organizations_organizational_unit.workloads_nonprod.id
}

resource "aws_organizations_policy_attachment" "nonprod_s3_ransomware" {
  policy_id = aws_organizations_policy.s3_ransomware_protection.id
  target_id = aws_organizations_organizational_unit.workloads_nonprod.id
}

# Quarantine OU Attachment (Isolates any compromised account moved here)
resource "aws_organizations_policy_attachment" "quarantine_lockdown" {
  policy_id = aws_organizations_policy.quarantine_isolation.id
  target_id = aws_organizations_organizational_unit.quarantine.id
}
