@echo off
REM Windows Batch Automated Runner for AWS Multi-Account Security Guardrails Engine
echo ============================================================
echo  AWS Multi-Account Security Governance & SCP Guardrails Engine
echo  Architect: Kosha Gohil ^| DevSecOps ^& Cloud Security
echo ============================================================

echo.
echo [1/4] Running Ruff Linter...
ruff check src tests
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Ruff linter failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/4] Running Pytest Suite...
pytest -v
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Pytest tests failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/4] Linting SCP Policies...
python -m src.cli lint-scp
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] SCP linting failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [4/4] Running Multi-Account Simulation...
python -m src.cli simulate
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Simulation failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo  [SUCCESS] All checks and simulations passed!
echo ============================================================
