@echo off
echo ============================================
echo  IDS Engine Starting...
echo ============================================
call venv\Scripts\activate.bat
set PYTHONPATH=%CD%

:: Check models exist
if not exist src\ml\models\isolation_forest.joblib (
    echo WARNING: Models not found. Running train.bat first...
    call train.bat
)

echo.
echo Starting IDS Engine...
echo Press Ctrl+C to stop.
echo.
echo NOTE: For live packet capture, run this window as Administrator.
echo       For PCAP mode (no admin needed), CAPTURE_MODE=pcap in .env
echo.
python -m src.main
pause
