@echo off
echo ============================================
echo  IDS Dashboard Starting...
echo ============================================
call venv\Scripts\activate.bat
set PYTHONPATH=%CD%
echo.
echo Dashboard will open at: http://localhost:8501
echo Press Ctrl+C to stop.
echo.
streamlit run src/dashboard/app.py --server.port=8501 --server.address=localhost
pause
