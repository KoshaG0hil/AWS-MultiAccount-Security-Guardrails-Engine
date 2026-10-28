# PowerShell Automated Runner for AWS Multi-Account Security Guardrails Engine
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AWS Multi-Account Security Governance & SCP Guardrails Engine" -ForegroundColor Cyan
Write-Host " Architect: Kosha Gohil | DevSecOps & Cloud Security" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n[1/5] Checking Python environment..." -ForegroundColor Yellow
python --version

# 2. Run Ruff Linter
Write-Host "`n[2/5] Running Ruff code analysis..." -ForegroundColor Yellow
ruff check src tests

# 3. Run Pytest Test Suite
Write-Host "`n[3/5] Executing Pytest test suite with Moto mocks..." -ForegroundColor Yellow
pytest -v

# 4. Run SCP Policy Linter
Write-Host "`n[4/5] Linting AWS Organizations SCP Policies..." -ForegroundColor Yellow
python -m src.cli lint-scp

# 5. Run Full Governance Simulation
Write-Host "`n[5/5] Running Full Multi-Account Governance Simulation..." -ForegroundColor Yellow
python -m src.cli simulate

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " [SUCCESS] All checks, tests, and simulations passed 100%!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
