# Hugging Face Spaces / generic container image for the IDS dashboard.
# Designed to run the Streamlit dashboard in demo mode against a bundled
# sample dataset. Live packet capture is not available inside an HF Space
# (no host network access) — set DASHBOARD_DEMO_MODE=true in the Space's
# Variables tab.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System packages: build-essential is needed for any C-extension wheel that
# doesn't ship a manylinux build for Python 3.11 (rare but happens with
# scapy/pyarrow on minor version bumps).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so layer cache survives source edits
COPY requirements_local.txt /app/requirements_local.txt
# Install CPU-only torch wheel to keep image size and cold-start sane on free
# tier — the Spaces free CPU tier doesn't have a GPU anyway.
RUN pip install --extra-index-url https://download.pytorch.org/whl/cpu \
        torch==2.6.0+cpu \
    && pip install -r requirements_local.txt

# App source
COPY . /app

# Pre-create runtime dirs so the engine doesn't fail at first launch.
RUN mkdir -p db logs data/raw data/processed data/baselines src/ml/models

# Train the three models on synthetic data at build time so the dashboard
# loads with real metrics out of the box (rather than the misleading
# hardcoded F1 0.95 numbers the old static mockup displayed). The training
# pipeline writes IF/RF/AE artefacts into src/ml/models/ and a metrics.json
# the dashboard reads. Falls back to synthetic make_classification because
# CICIDS2017 isn't bundled in the image.
ENV PYTHONPATH=/app
RUN python -m src.ml.train 2>&1 | tail -50

# HF Spaces sends traffic to port 7860 by default; map Streamlit there.
ENV STREAMLIT_SERVER_PORT=7860 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    DASHBOARD_DEMO_MODE=true \
    CAPTURE_MODE=pcap

EXPOSE 7860

# Point Streamlit directly at the dashboard module. The streamlit_app.py shim
# at the repo root uses importlib.import_module() which only executes the
# dashboard's top-level render code ONCE on first import — Streamlit's rerun
# model needs the script to re-execute on every interaction, so the shim
# leaves the iframe blank after the first paint. Bypassing it fixes this.
CMD ["streamlit", "run", "src/dashboard/app.py", "--server.port=7860", "--server.address=0.0.0.0", "--server.enableXsrfProtection=false"]
