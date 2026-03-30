"""
Top-level entry point for Streamlit Cloud deployment.
Just imports and runs the actual dashboard from src/dashboard/app.py
"""
import subprocess
import sys

# streamlit cloud runs this file, but the real app lives in src/dashboard/app.py
# so we just re-run streamlit on that file
if __name__ == "__main__":
    subprocess.run([sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py"])
else:
    # when streamlit executes this directly, redirect to the real app
    import importlib
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    importlib.import_module("src.dashboard.app")
