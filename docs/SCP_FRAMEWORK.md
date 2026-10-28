# Service Control Policy (SCP) Engineering Framework

## 1. Overview & Evaluation Logic

Service Control Policies (SCPs) in AWS Organizations set the maximum permissions for account members. Unlike IAM policies which grant permissions, **SCPs filter and constrain permissions**. 

Key evaluation rules:
1. **Explicit Deny Precedence**: An explicit `Deny` statement in any applied SCP overrides any and all `Allow` statements in IAM policies or downstream SCPs.
2. **Inheritance & Traversal**: An account is subject to all SCPs attached to its parent OU, its grandparent OUs, and the Organization Root (`FullAWSAccess` baseline must remain attached to permit explicit Allow pathways).
3. **Hard Size Limit**: AWS strictly enforces a maximum size of **5,120 bytes** per SCP document. Every byte counts; our custom linter (`src/scanners/scp_linter.py`) validates size compliance before deployment.

---

## 2. Policy Suite Catalog

### SCP 01: Geographic Region Restriction
- **File**: `policies/scps/01_region_restriction.json`
- **Target**: Organization Root (`r-09a8`)
- **Size**: 1,411 bytes (27.5% capacity)
- **Mechanism**: Utilizes `Effect: Deny` with `Condition: { StringNotEquals: { aws:RequestedRegion: [...] } }` and an extensive `NotAction` whitelist for AWS global services (CloudFront, Route53, IAM, STS, Organizations, Support).
- **Approved Regions**: `us-east-1`, `us-west-2`.

### SCP 02: Member Account Root User Denial
- **File**: `policies/scps/02_root_user_denial.json`
- **Target**: Organization Root (`r-09a8`)
- **Size**: 322 bytes (6.2% capacity)
- **Mechanism**: Denies all operations (`Action: "*"`) where `aws:PrincipalArn` matches `arn:aws:iam::*:root`. Enforces centralized IAM Identity Center (SSO) and eliminates root credential leakage vulnerabilities.

### SCP 03: Security Telemetry & Log Protection
- **File**: `policies/scps/03_security_services_protection.json`
- **Target**: Workloads (Prod & Non-Prod OUs)
- **Size**: 982 bytes (19.1% capacity)
- **Mechanism**: Denies deletion, disabling, or tampering with:
  - AWS CloudTrail (`cloudtrail:DeleteTrail`, `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail`)
  - Amazon GuardDuty (`guardduty:DeleteDetector`, `guardduty:DisassociateFromMasterAccount`)
  - AWS Config (`config:DeleteConfigurationRecorder`, `config:StopConfigurationRecorder`)
  - AWS Security Hub (`securityhub:DisableSecurityHub`)

### SCP 04: Network Perimeter Ingress / Egress Guardrails
- **File**: `policies/scps/04_network_perimeter_guardrails.json`
- **Target**: Workloads (Prod OU)
- **Size**: 679 bytes (13.2% capacity)
- **Mechanism**: Restricts `ec2:CreateInternetGateway` and `ec2:AttachInternetGateway` unless the resource carries the verified enterprise approval tag `aws:RequestTag/NetworkApproval == "EnterpriseSecApproved"`. Prevents accidental or rogue direct Internet exposure.

### SCP 05: S3 Ransomware & Bucket Tampering Protection
- **File**: `policies/scps/05_s3_ransomware_protection.json`
- **Target**: All Workload OUs
- **Size**: 630 bytes (12.3% capacity)
- **Mechanism**: 
  - Prevents modifying or removing S3 Account Public Access Block (`s3:PutAccountPublicAccessBlock`, `s3:DeleteAccountPublicAccessBlock`).
  - Denies deletion of S3 Object Lock retention configurations (`s3:BypassGovernanceRetention`, `s3:PutBucketObjectLockConfiguration`).

### SCP 06: Quarantine Isolation Containment Policy
- **File**: Synthesized dynamically in Terraform (`terraform/scps.tf`) and CLI (`src/remediation/account_quarantine.py`)
- **Target**: Quarantine OU
- **Size**: 412 bytes (8.0% capacity)
- **Mechanism**: Denies all actions across all services (`Action: "*"`, `Resource: "*"`) with an explicit exemption for the emergency incident response role (`arn:aws:iam::*:role/EmergencyIncidentResponseRole`) and essential AWS internal service-linked roles.

---

## 3. Automated Validation & Linting

Before pushing or applying any SCP changes, run the automated linter:

```bash
python -m src.cli lint-scp
```

The linter validates:
- [x] Valid JSON syntax
- [x] Document size $\le$ 5,120 bytes
- [x] Presence of `Version: "2012-10-17"`
- [x] Correct statement syntax (`Effect: Deny`, `Action`/`NotAction`, `Resource`)
- [x] Proper Condition block structure
