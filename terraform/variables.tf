variable "aws_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Target deployment environment (production, staging, sandbox)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name tag and identifier"
  type        = string
  default     = "aws-guardrails-engine"
}

variable "org_feature_set" {
  description = "AWS Organization feature set (ALL or CONSOLIDATED_BILLING)"
  type        = string
  default     = "ALL"
}

variable "allowed_regions" {
  description = "List of approved AWS regions for workloads"
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "quarantine_ou_name" {
  description = "Name for the quarantine organizational unit"
  type        = string
  default     = "Quarantine"
}

variable "enable_eventbridge_remediation" {
  description = "Whether to deploy the automated EventBridge drift remediation pipeline"
  type        = bool
  default     = true
}

variable "ir_emergency_role_arn" {
  description = "ARN of the Incident Response emergency break-glass role permitted in Quarantine"
  type        = string
  default     = "arn:aws:iam::*:role/EmergencyIncidentResponseRole"
}
