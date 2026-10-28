# How to Run & Verify the AWS Multi-Account Security Guardrails Engine

This guide provides end-to-end instructions for running, testing, and deploying the AWS Multi-Account Security Governance & SCP Guardrails Engine locally or within CI/CD.

---

## 1. Prerequisites

- **Python 3.11+** installed (`python --version` or `py -3.11 --version`)
- **Terraform 1.5+** installed (optional, for IaC validation)
- **AWS CLI v2** configured (optional for dry-run/mock mode, required for live multi-account deployments)

---

## 2. Windows Quickstart (PowerShell)

```powershell
# Navigate to project directory
cd "c:\Users\gohil\Desktop\AWS\AWS-MultiAccount-Security-Guardrails-Engine"

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run complete test suite (13 tests, 100% pass)
pytest -v

# Run SCP policy linter
python -m src.cli lint-scp

# Run full simulation of multi-account drift detection & self-healing
python -m src.cli simulate
```

Or execute the automated runner script:
```powershell
.\run.ps1
```

---

## 3. Linux / macOS Quickstart (Bash)

```bash
# Clone and enter directory
cd AWS-MultiAccount-Security-Guardrails-Engine

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest -v

# Execute automated runner
chmod +x run.sh
./run.sh
```

---

## 4. Docker Quickstart

```bash
# Build the container image
docker build -t aws-guardrails-engine .

# Run the container (executes tests and simulation)
docker run --rm aws-guardrails-engine
```

---

## 5. Terraform Infrastructure Validation

```bash
cd terraform

# Initialize providers
terraform init -backend=false

# Check syntax and configuration
terraform validate

# View planned resources
terraform plan -var-file=terraform.tfvars.example
```

---

## 6. Interactive Cyber SOC Console

Open `index.html` in any modern web browser:
```powershell
# Windows
Start-Process index.html

# macOS
open index.html

# Linux
xdg-open index.html
```

Or view the hosted version on GitHub Pages:
[https://koshag0hil.github.io/AWS-MultiAccount-Security-Guardrails-Engine/](https://koshag0hil.github.io/AWS-MultiAccount-Security-Guardrails-Engine/)
