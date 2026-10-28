# SCP 01: Enforce Region Restriction
resource "aws_organizations_policy" "region_restriction" {
  name        = "Guardrail-01-Region-Restriction"
  description = "Denies all AWS service API calls outside approved regions except global control plane services."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/../policies/scps/01_region_restriction.json")

  tags = merge(local.common_tags, {
    GuardrailLevel = "Organization-Root"
    RuleCode       = "SCP-01-REG-RESTRICT"
  })
}

# SCP 02: Deny Root Account Operations
resource "aws_organizations_policy" "root_user_denial" {
  name        = "Guardrail-02-Root-User-Denial"
  description = "Denies all actions by the root user principal in member accounts to enforce federated IAM access."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/../policies/scps/02_root_user_denial.json")

  tags = merge(local.common_tags, {
    GuardrailLevel = "Organization-Root"
    RuleCode       = "SCP-02-ROOT-DENY"
  })
}

# SCP 03: Protect Security Services & Prevent Tampering
resource "aws_organizations_policy" "security_services_protection" {
  name        = "Guardrail-03-Security-Services-Protection"
  description = "Prevents disabling CloudTrail, GuardDuty, AWS Config, Security Hub, and tampering with security policies."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/../policies/scps/03_security_services_protection.json")

  tags = merge(local.common_tags, {
    GuardrailLevel = "All-Workloads"
    RuleCode       = "SCP-03-SEC-PROTECT"
  })
}

# SCP 04: Network Perimeter Guardrails (Prevent Rogue IGWs)
resource "aws_organizations_policy" "network_perimeter_guardrails" {
  name        = "Guardrail-04-Network-Perimeter-Guardrails"
  description = "Restricts creation or attachment of Internet Gateways without enterprise authorization tags."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/../policies/scps/04_network_perimeter_guardrails.json")

  tags = merge(local.common_tags, {
    GuardrailLevel = "Workloads"
    RuleCode       = "SCP-04-NET-PERIMETER"
  })
}

# SCP 05: S3 Ransomware & Bucket Tampering Protection
resource "aws_organizations_policy" "s3_ransomware_protection" {
  name        = "Guardrail-05-S3-Ransomware-Protection"
  description = "Blocks public access disabling, bucket deletion without MFA, and Object Lock tampering."
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.module}/../policies/scps/05_s3_ransomware_protection.json")

  tags = merge(local.common_tags, {
    GuardrailLevel = "All-Workloads"
    RuleCode       = "SCP-05-S3-PROTECT"
  })
}

# SCP 06: Quarantine Isolation Containment Policy
resource "aws_organizations_policy" "quarantine_isolation" {
  name        = "Guardrail-06-Quarantine-Isolation-Policy"
  description = "Compromised Account Containment: Denies all API actions except emergency Incident Response role."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllExceptEmergencyIRRole"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              var.ir_emergency_role_arn,
              "arn:aws:iam::*:role/aws-service-role/*"
            ]
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    GuardrailLevel = "Quarantine-OU"
    RuleCode       = "SCP-06-QUARANTINE"
  })
}
