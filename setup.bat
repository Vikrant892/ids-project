@echo off
echo ============================================
echo  Hybrid ML IDS — Windows Setup
echo ============================================

python --version 2>nul
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

echo.
echo [1/5] Creating virtual environment...
python -m venv venv
if errorlevel 1 ( echo ERROR: venv failed & pause & exit /b 1 )

echo [2/5] Activating venv...
call venv\Scripts\activate.bat

echo [3/5] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo [4/5] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Install failed. Try:
    echo   venv\Scripts\activate
    echo   pip install -r requirements.txt --no-cache-dir
    pause & exit /b 1
)

echo [5/5] Creating directories and initialising database...
mkdir data\raw 2>nul
mkdir data\processed 2>nul
mkdir data\pcap 2>nul
mkdir data\baselines 2>nul
mkdir db 2>nul
mkdir logs 2>nul
mkdir src\ml\models 2>nul

echo Copying .env with correct Windows settings...
copy /Y .env.example .env

set PYTHONPATH=%CD%
python -c "from src.utils.db import init_db; init_db()"

echo.
echo ============================================
echo  Setup complete! Run in this order:
echo    1. generate_test_pcap.bat
echo    2. train.bat
echo    3. start.bat       (Terminal 1)
echo    4. dashboard.bat   (Terminal 2)
echo ============================================
pause
