# AWS Multi-Account Security Governance & SCP Guardrails Engine

[![Build Status](https://github.com/KoshaG0hil/AWS-MultiAccount-Security-Guardrails-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/KoshaG0hil/AWS-MultiAccount-Security-Guardrails-Engine/actions/workflows/ci.yml)
[![Pages Deployment](https://github.com/KoshaG0hil/AWS-MultiAccount-Security-Guardrails-Engine/actions/workflows/pages.yml/badge.svg)](https://koshag0hil.github.io/AWS-MultiAccount-Security-Guardrails-Engine/)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.5.0-623ce4.svg)](https://www.terraform.io/)
[![Compliance](https://img.shields.io/badge/Compliance-CIS%20AWS%20v3.0%20%7C%20NIST%20CSF-emerald.svg)](https://www.cisecurity.org/)
[![Coverage](https://img.shields.io/badge/Tests-100%25%20Passing%20(Pytest%2BMoto)-brightgreen.svg)](https://github.com/KoshaG0hil/AWS-MultiAccount-Security-Guardrails-Engine)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Enterprise-grade landing zone governance, Service Control Policy (SCP) guardrail enforcement, multi-account compliance drift detection, and autonomous self-healing remediation mesh for AWS Organizations.**

🔗 **Live Interactive Cyber SOC Console & Simulator:** [https://koshag0hil.github.io/AWS-MultiAccount-Security-Guardrails-Engine/](https://koshag0hil.github.io/AWS-MultiAccount-Security-Guardrails-Engine/)

---

## Architecture Overview

```text
                                 +------------------------------+
                                 |     AWS Organization Root    |
                                 |         (r-09a8)             |
                                 +--------------+---------------+
                                                |
               +--------------------------------+-------------------------------+
               |                                |                               |
               v                                v                               v
  +-------------------------+      +-------------------------+      +-------------------------+
  |         Core OU         |      |   Workloads (Prod) OU   |      | Workloads (Non-Prod) OU |
  +------------+------------+      +------------+------------+      +------------+------------+
               |                                |                                |
       +-------+-------+                +-------+-------+                +-------+-------+
       |               |                |               |                |               |
       v               v                v               v                v               v
+-------------+ +-------------+  +-------------+ +-------------+  +-------------+ +-------------+
| 222233334444| | 333344445555|  | 444455556666| | 555566667777|  | 666677778888| | 777788889999|
| Security &  | | Shared      |  | Payment     | | Customer    |  | Dev         | | Staging     |
| Log Archive | | Services    |  | Processing  | | Database    |  | Sandbox     | | Cluster     |
+-------------+ +-------------+  +-------------+ +-------------+  +-------------+ +-------------+
                                                                                 |
                                                                                 | (Drift / Breach Detected)
                                                                                 v
                                                                    +-------------------------+
                                                                    |      Quarantine OU      |
                                                                    |  (Isolation Containment)|
                                                                    +------------+------------+
                                                                                 |
                                                                                 v
                                                                          +-------------+
                                                                          | 999900001111|
                                                                          | Compromised |
                                                                          | Member Host |
                                                                          +-------------+
```

---

## Key Capabilities

1. **Production Service Control Policy (SCP) Framework**:
   - `01_region_restriction.json`: Denies API calls outside approved regions (`us-east-1`, `us-west-2`) with an explicit whitelist for AWS global control plane services.
   - `02_root_user_denial.json`: Prevents member account root user actions to enforce centralized SSO and eliminate credential theft risks.
   - `03_security_services_protection.json`: Hardens AWS CloudTrail, GuardDuty, AWS Config, and Security Hub against disabling or tampering.
   - `04_network_perimeter_guardrails.json`: Restricts Internet Gateway creation and attachment without verified enterprise security tags.
   - `05_s3_ransomware_protection.json`: Enforces S3 Account Public Access Block and protects Object Lock governance retention configurations.
   - `06_quarantine_isolation.json`: Zero-trust Deny-All containment policy applied to compromised accounts with an emergency break-glass role exemption.

2. **Automated SCP Policy Linter**:
   - Validates JSON formatting, structural statements (`Effect: Deny`, `Condition`), and verifies strict adherence to the AWS Organizations **5,120-byte document limit**.

3. **Multi-Account Compliance Drift Scanner**:
   - Evaluates member accounts against CIS AWS Foundations Benchmark v3.0.
   - Detects rogue Internet Gateways, unencrypted EBS volumes, deactivated S3 public access blocks, and suspended CloudTrail recording.

4. **EventBridge & Lambda Self-Healing Remediation Mesh**:
   - Near-instantaneous response to AWS Config compliance violations.
   - Autonomously restores S3 public access blocks, detaches rogue IGWs, and restarts CloudTrail recording with audit event logging.

5. **Automated Account Quarantine & Forensics Containment**:
   - Dynamically shifts high-risk or compromised accounts into the Quarantine OU via AWS Organizations API.
   - Instantly applies lockdown policies, isolating lateral movement and reducing breach blast radius to zero.

6. **Infrastructure as Code (Terraform)**:
   - Full Terraform module (`terraform/`) deploying the Organization structure, OUs, SCP policies, policy attachments, AWS Config rules, and EventBridge self-healing mesh.

---

## Quickstart & CLI Commands

### 1. Installation
```bash
git clone https://github.com/KoshaG0hil/AWS-MultiAccount-Security-Guardrails-Engine.git
cd AWS-MultiAccount-Security-Guardrails-Engine
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Lint & Validate SCP Policies
```bash
python -m src.cli lint-scp
```

### 3. Run Drift Scanner & Compliance Evaluation
```bash
# Scan a specific account
python -m src.cli scan-drift --account-id 666677778888

# Scan and automatically remediate violations
python -m src.cli scan-drift --account-id 666677778888 --remediate
```

### 4. Account Quarantine & Isolation
```bash
# Move compromised account to Quarantine OU
python -m src.cli quarantine --account-id 666677778888

# Release account post-incident investigation
python -m src.cli release --account-id 666677778888 --destination-ou ou-workloads-nonprod
```

### 5. Generate Auditable Compliance Manifest
```bash
python -m src.cli generate-manifest --output reports/compliance_manifest.json
```

### 6. Run Complete Test Suite
```bash
pytest -v
```

---

## Terraform Deployment

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

---

## Directory Structure

```text
AWS-MultiAccount-Security-Guardrails-Engine/
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Continuous integration (Ruff, Pytest, Moto, Terraform)
│       └── pages.yml                  # GitHub Pages automated deployment
├── docs/
│   ├── ARCHITECTURE.md                # Multi-account landing zone architecture design
│   ├── SCP_FRAMEWORK.md               # SCP engineering framework and evaluation logic
│   └── RUNBOOKS.md                    # SecOps incident containment and response runbooks
├── policies/
│   └── scps/
│       ├── 01_region_restriction.json
│       ├── 02_root_user_denial.json
│       ├── 03_security_services_protection.json
│       ├── 04_network_perimeter_guardrails.json
│       └── 05_s3_ransomware_protection.json
├── reports/                           # Output audit and compliance manifests
├── src/
│   ├── core/
│   │   ├── config.py                  # Governance configuration and baseline rules
│   │   └── __init__.py
│   ├── remediation/
│   │   ├── account_quarantine.py      # Automated account containment & OU relocation
│   │   ├── self_healing_enforcer.py   # Autonomous remediation engine
│   │   └── __init__.py
│   ├── reporters/
│   │   ├── compliance_manifest.py     # JSON audit manifest generator & signer
│   │   └── __init__.py
│   ├── scanners/
│   │   ├── drift_scanner.py           # Multi-account drift detection & scoring
│   │   ├── scp_linter.py              # AWS Organizations SCP size & syntax validator
│   │   └── __init__.py
│   ├── cli.py                         # Unified operator CLI interface
│   └── lambda_drift_handler.py        # EventBridge drift remediation Lambda handler
├── terraform/
│   ├── config_rules.tf                # AWS Config organization rules
│   ├── eventbridge_remediation.tf     # EventBridge rule, IAM role, and Lambda function
│   ├── main.tf                        # Provider configuration and locals
│   ├── organizations.tf               # AWS Organizations & OU hierarchy
│   ├── outputs.tf                     # Organization IDs and resource ARNs
│   ├── policy_attachments.tf          # SCP target bindings
│   ├── scps.tf                        # Service Control Policy definitions
│   ├── terraform.tfvars.example       # Example variables
│   └── variables.tf                   # Input variables
├── tests/                             # 100% pass unit & mock integration tests (Moto)
│   ├── test_account_quarantine.py
│   ├── test_compliance_manifest.py
│   ├── test_drift_scanner.py
│   ├── test_lambda_drift_handler.py
│   ├── test_scp_linter.py
│   └── test_self_healing.py
├── index.html                         # Interactive Cyber SOC Console & Simulator
├── pyproject.toml                     # Python tool configurations (Ruff, Pytest)
├── requirements.txt                   # Production dependencies
├── LICENSE                            # MIT License
└── README.md
```

---

## Author & Engineering Attribution

**Kosha Gohil**  
*AWS Cloud Security & DevSecOps Engineer*  
- **LinkedIn:** [linkedin.com/in/kosha-gohil](https://www.linkedin.com/in/kosha-gohil/)  
- **GitHub:** [@KoshaG0hil](https://github.com/KoshaG0hil)
