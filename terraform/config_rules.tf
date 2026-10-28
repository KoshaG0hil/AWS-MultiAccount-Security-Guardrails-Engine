# AWS Config Organization Managed Rules for Continuous Compliance

resource "aws_config_organization_managed_rule" "s3_public_read_prohibited" {
  name            = "org-s3-bucket-public-read-prohibited"
  rule_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  description     = "Checks that your Amazon S3 buckets do not allow public read access."

  depends_on = [aws_organizations_organization.org]
}

resource "aws_config_organization_managed_rule" "root_account_mfa" {
  name            = "org-root-account-mfa-enabled"
  rule_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  description     = "Checks whether the root user in member accounts has MFA enabled."

  depends_on = [aws_organizations_organization.org]
}

resource "aws_config_organization_managed_rule" "cloudtrail_enabled" {
  name            = "org-cloudtrail-enabled"
  rule_identifier = "CLOUD_TRAIL_ENABLED"
  description     = "Checks whether AWS CloudTrail is enabled and sending logs in all member accounts."

  depends_on = [aws_organizations_organization.org]
}

resource "aws_config_organization_managed_rule" "encrypted_volumes" {
  name            = "org-encrypted-volumes"
  rule_identifier = "ENCRYPTED_VOLUMES"
  description     = "Checks whether EBS volumes attached to EC2 instances are encrypted."

  depends_on = [aws_organizations_organization.org]
}
