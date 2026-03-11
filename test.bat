@echo off
echo ============================================
echo  Running IDS Test Suite
echo ============================================
call venv\Scripts\activate.bat
set PYTHONPATH=%CD%
set DB_PATH=db\test_ids.sqlite
set CAPTURE_MODE=pcap
set LOG_LEVEL=WARNING
echo.
python -m pytest tests\unit\ tests\integration\ tests\simulation\ -v --cov=src --cov-report=term-missing
pause
