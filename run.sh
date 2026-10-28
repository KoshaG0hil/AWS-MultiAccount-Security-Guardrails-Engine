#!/usr/bin/env bash
# Linux / macOS Automated Runner for AWS Multi-Account Security Guardrails Engine
set -euo pipefail

echo "============================================================"
echo " AWS Multi-Account Security Governance & SCP Guardrails Engine"
echo " Architect: Kosha Gohil | DevSecOps & Cloud Security"
echo "============================================================"

echo ""
echo "[1/4] Running Ruff Linter..."
ruff check src tests

echo ""
echo "[2/4] Executing Pytest Suite..."
pytest -v

echo ""
echo "[3/4] Linting Service Control Policies..."
python3 -m src.cli lint-scp

echo ""
echo "[4/4] Executing Multi-Account Simulation..."
python3 -m src.cli simulate

echo ""
echo "============================================================"
echo " [SUCCESS] All checks and simulations passed 100%!"
echo "============================================================"
