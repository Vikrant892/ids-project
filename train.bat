@echo off
echo ============================================
echo  IDS — ML Training Pipeline
echo ============================================
call venv\Scripts\activate.bat
echo.
echo Training all 3 models (Isolation Forest + Random Forest + Autoencoder)
echo This takes 5-10 minutes on first run.
echo Synthetic data will be auto-generated if data\raw\ is empty.
echo.
set PYTHONPATH=%CD%
python -m src.ml.train
if errorlevel 1 (
    echo.
    echo ERROR: Training failed. Check logs above.
    pause
    exit /b 1
)
echo.
echo Models saved to src\ml\models\
echo You can now run start.bat
pause
