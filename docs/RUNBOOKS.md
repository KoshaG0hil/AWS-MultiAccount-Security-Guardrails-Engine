# Security Operations (SecOps) Incident Response Runbooks

## Runbook 1: Immediate Account Containment & Quarantine

### Objective
Isolate an active, compromised member account to eliminate lateral movement, data exfiltration, or resource hijacking while preserving forensic state for analysis.

### Trigger Conditions
- Amazon GuardDuty finding: Severity $\ge$ 8.0 (e.g., `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom`, `Trojan:EC2/DNSDataExfiltration`).
- Confirmed credential compromise of administrative IAM principals.
- Mass unauthorized modifications to security configurations or data stores.

### Execution Procedure

1. **Execute CLI Quarantine**:
   ```bash
   python -m src.cli quarantine --account-id 666677778888
   ```

2. **Verify State Transition**:
   - Confirm the account has been relocated from `ou-workloads-nonprod` to `ou-quarantine-980`.
   - Confirm `Guardrail-06-Quarantine-Isolation-Policy` is actively attached.
   - Run verification probe:
     ```bash
     aws organizations list-parents --child-id 666677778888
     ```

3. **Forensic Access via Break-Glass Role**:
   - SecOps investigators assume `arn:aws:iam::666677778888:role/EmergencyIncidentResponseRole` using hardware MFA tokens.
   - Capture live memory, EBS snapshots, and CloudTrail forensic evidence.

---

## Runbook 2: Self-Healing Drift Remediation

### Objective
Detect and resolve drift from baseline security configurations autonomously without requiring manual engineer intervention.

### Automatic Workflow
1. AWS Config identifies drift (e.g., S3 Public Access Block turned off).
2. EventBridge captures `Config Rules Compliance Change` with `complianceType = "NON_COMPLIANT"`.
3. EventBridge triggers `aws-guardrails-engine-drift-remediator` Lambda.
4. Lambda parses the violation, verifies account OU context, and invokes `SelfHealingEnforcer`.
5. Automated corrective actions taken:
   - S3 Public Access Block restored.
   - Rogue Internet Gateway detached from VPC.
   - CloudTrail logging stream restarted.
6. CloudWatch alert published and incident ticket closed.

### Manual On-Demand Execution
If autonomous remediation is toggled to dry-run or manual mode:
```bash
# Scan and remediate single account
python -m src.cli scan-drift --account-id 666677778888 --remediate

# Generate compliance manifest
python -m src.cli generate-manifest --output reports/compliance_manifest.json
```

---

## Runbook 3: Account De-Quarantine & Re-Integration

### Objective
Safely return an account to normal production status following incident eradication and validation.

### Prerequisites
- Threat eradicated, compromised credentials revoked, infected instances terminated.
- Post-incident forensic snapshot archived in Security Account (`222233334444`).
- Approval sign-off from Head of Information Security.

### Execution Procedure
```bash
python -m src.cli release --account-id 666677778888 --destination-ou ou-workloads-nonprod
```

Verify account health and scan baseline compliance:
```bash
python -m src.cli scan-drift --account-id 666677778888
```
Ensure compliance score is 100% before restoring production traffic.
