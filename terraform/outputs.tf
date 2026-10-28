output "organization_id" {
  description = "The unique identifier of the AWS Organization"
  value       = aws_organizations_organization.org.id
}

output "organization_arn" {
  description = "The ARN of the AWS Organization"
  value       = aws_organizations_organization.org.arn
}

output "organization_root_id" {
  description = "The Root ID of the AWS Organization"
  value       = aws_organizations_organization.org.roots[0].id
}

output "ou_ids" {
  description = "Map of Organizational Unit names to their AWS IDs"
  value = {
    core              = aws_organizations_organizational_unit.core.id
    workloads_prod    = aws_organizations_organizational_unit.workloads_prod.id
    workloads_nonprod = aws_organizations_organizational_unit.workloads_nonprod.id
    quarantine        = aws_organizations_organizational_unit.quarantine.id
  }
}

output "scp_ids" {
  description = "Map of Service Control Policies to their Policy IDs"
  value = {
    region_restriction           = aws_organizations_policy.region_restriction.id
    root_user_denial             = aws_organizations_policy.root_user_denial.id
    security_services_protection = aws_organizations_policy.security_services_protection.id
    network_perimeter_guardrails = aws_organizations_policy.network_perimeter_guardrails.id
    s3_ransomware_protection     = aws_organizations_policy.s3_ransomware_protection.id
    quarantine_isolation         = aws_organizations_policy.quarantine_isolation.id
  }
}

output "remediation_lambda_arn" {
  description = "ARN of the automated drift remediation Lambda function"
  value       = aws_lambda_function.drift_remediator.arn
}

output "compliance_eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule capturing compliance drift"
  value       = aws_cloudwatch_event_rule.compliance_drift_rule.arn
}
