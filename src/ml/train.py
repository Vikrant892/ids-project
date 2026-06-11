"""
ML Training Pipeline.
Ingests CICIDS2017 CSVs, engineers features in the EXACT order produced by
src.nids.feature_extractor.extract_features at inference time, trains all three
models, evaluates on a held-out test set, and serialises both the models and a
metrics JSON file the dashboard reads to display real benchmark numbers.

Usage:
    python -m src.ml.train
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from src.ml.autoencoder import AutoencoderModel
from src.ml.isolation_forest import IFModel
from src.ml.random_forest import RFModel
from src.nids.feature_extractor import FEATURE_NAMES, NUM_FEATURES
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

CICIDS_LABEL_COL = "Label"
CICIDS_BENIGN_LABEL = "BENIGN"

METRICS_PATH = Path(config.MODEL_DIR) / "metrics.json"


def load_cicids(data_dir: str) -> pd.DataFrame:
    """
    Load and concatenate all CICIDS2017 CSV files from data_dir.
    Returns dataframe with feature columns + binary label.
    """
    csv_files = list(Path(data_dir).glob("*.csv"))
    if not csv_files:
        logger.error("no_cicids_csvs_found", dir=data_dir)
        raise FileNotFoundError(f"No CSV files in {data_dir}")

    dfs = []
    for f in csv_files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        logger.info("loaded_csv", file=str(f), rows=len(df))

    df = pd.concat(dfs, ignore_index=True)
    logger.info("total_rows_loaded", rows=len(df))
    return df


def _col(df: pd.DataFrame, *candidates: str, default: float = 0.0) -> pd.Series:
    """
    Return the first matching column from `candidates` (case-insensitive,
    whitespace-tolerant). If none exist, return a constant Series.
    CICIDS2017 column names vary between dump files (leading spaces, mixed case),
    so we normalise here rather than at every call site.
    """
    norm = {c.strip().lower(): c for c in df.columns}
    for cand in candidates:
        key = cand.strip().lower()
        if key in norm:
            return pd.to_numeric(df[norm[key]], errors="coerce").fillna(default)
    return pd.Series(default, index=df.index, dtype=np.float64)


def preprocess(df: pd.DataFrame) -> tuple:
    """
    Map CICIDS2017 columns into the EXACT feature order produced by
    src.nids.feature_extractor.extract_features at inference time.

    This is correctness-critical: training and inference must produce
    identically-ordered feature vectors or the models learn the wrong
    correlations. The previous implementation mapped CICIDS columns into
    slots 0..14 in CICIDS order, which did not match FEATURE_NAMES.

    Returns (X_benign, X_all, y_all).
    """
    # Drop rows with inf / NaN labels
    df = df.replace([float("inf"), float("-inf")], float("nan"))
    df = df.dropna(subset=[CICIDS_LABEL_COL])
    df["binary_label"] = (df[CICIDS_LABEL_COL] != CICIDS_BENIGN_LABEL).astype(int)

    # Pull source columns (case/whitespace-tolerant)
    fwd_packets = _col(df, "Total Fwd Packets")
    bwd_packets = _col(df, "Total Backward Packets", "Total Bwd Packets")
    fwd_bytes = _col(df, "Total Length of Fwd Packets", "Fwd Packets Length Total")
    bwd_bytes = _col(df, "Total Length of Bwd Packets", "Bwd Packets Length Total")
    duration_us = _col(df, "Flow Duration")  # microseconds in CICIDS2017
    pkt_rate = _col(df, "Flow Packets/s")
    byte_rate = _col(df, "Flow Bytes/s")
    syn_count = _col(df, "SYN Flag Count")
    fin_count = _col(df, "FIN Flag Count")
    rst_count = _col(df, "RST Flag Count")
    dst_port = _col(df, "Destination Port", "Dst Port")
    src_port = _col(df, "Source Port", "Src Port")
    proto_num = _col(df, "Protocol")

    # Derived
    duration_ms = (duration_us / 1000.0).clip(lower=0.001)
    total_packets = (fwd_packets + bwd_packets).clip(lower=1)
    total_bytes = (fwd_bytes + bwd_bytes).clip(lower=0)
    avg_pkt_size = total_bytes / total_packets
    fwd_bwd_ratio = fwd_packets / bwd_packets.clip(lower=1)

    # Build feature matrix in FEATURE_NAMES order
    columns = {
        "duration_ms":          duration_ms,
        "total_packets":        total_packets,
        "total_bytes":          total_bytes,
        "fwd_packets":          fwd_packets,
        "bwd_packets":          bwd_packets,
        "fwd_bytes":            fwd_bytes,
        "bwd_bytes":            bwd_bytes,
        "pkt_rate":             pkt_rate.clip(lower=0.001),
        "byte_rate":            byte_rate.clip(lower=0.001),
        "fwd_bwd_ratio":        fwd_bwd_ratio,
        "avg_pkt_size":         avg_pkt_size,
        "has_syn":              (syn_count > 0).astype(np.float32),
        "has_fin":              (fin_count > 0).astype(np.float32),
        "has_rst":              (rst_count > 0).astype(np.float32),
        "dst_port_well_known":  (dst_port < 1024).astype(np.float32),
        "dst_port_registered":  ((dst_port >= 1024) & (dst_port < 49152)).astype(np.float32),
        "dst_port_ephemeral":   (dst_port >= 49152).astype(np.float32),
        "src_port_privileged":  (src_port < 1024).astype(np.float32),
        "is_tcp":               (proto_num == 6).astype(np.float32),
        "is_udp":               (proto_num == 17).astype(np.float32),
        "is_icmp":              (proto_num == 1).astype(np.float32),
        "log_total_bytes":      np.log1p(total_bytes),
        "log_pkt_rate":         np.log1p(pkt_rate.clip(lower=0)),
        "log_byte_rate":        np.log1p(byte_rate.clip(lower=0)),
    }
    # Sanity-check ordering
    assert list(columns.keys()) == FEATURE_NAMES, (
        "Training feature order does not match FEATURE_NAMES - would cause "
        "silent training/inference schema drift."
    )

    X = np.column_stack([columns[name].to_numpy(dtype=np.float32) for name in FEATURE_NAMES])
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)
    X = np.clip(X, 0, 1e9)

    y = df["binary_label"].to_numpy(dtype=np.int8)
    X_benign = X[y == 0]

    attack_rate = round(float(y.mean()) * 100, 2)
    logger.info(
        "preprocessing_complete",
        total=len(X),
        benign=int((y == 0).sum()),
        attack=int((y == 1).sum()),
        attack_rate=f"{attack_rate}%",
        n_features=NUM_FEATURES,
    )

    return X_benign, X, y


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray, name: str) -> dict:
    """
    Compute classification metrics for a trained model.
    Returns a dict suitable for the metrics.json file consumed by the dashboard.
    """
    preds = np.array([model.predict(x) for x in X_test])
    scores = np.array([model.score(x) for x in X_test])
    print(f"\n{'='*50}")
    print(f"Model: {name}")
    print(classification_report(y_test, preds, target_names=["BENIGN", "ATTACK"], zero_division=0))
    try:
        auc = float(roc_auc_score(y_test, scores))
        print(f"ROC-AUC: {auc:.4f}")
    except Exception:
        auc = float("nan")
    return {
        "name":      name,
        "precision": float(precision_score(y_test, preds, pos_label=1, zero_division=0)),
        "recall":    float(recall_score(y_test, preds, pos_label=1, zero_division=0)),
        "f1":        float(f1_score(y_test, preds, pos_label=1, zero_division=0)),
        "roc_auc":   auc,
        "n_test":    int(len(y_test)),
    }


def _ensemble_metrics(if_m, rf_m, ae_m, X_test, y_test) -> dict:
    """Compute majority-vote ensemble metrics."""
    if_pred = np.array([if_m.predict(x) for x in X_test])
    rf_pred = np.array([rf_m.predict(x) for x in X_test])
    ae_pred = np.array([ae_m.predict(x) for x in X_test])
    votes = if_pred + rf_pred + ae_pred
    ens_pred = (votes >= 2).astype(int)

    if_score = np.array([if_m.score(x) for x in X_test])
    rf_score = np.array([rf_m.score(x) for x in X_test])
    ae_score = np.array([ae_m.score(x) for x in X_test])
    ens_score = 0.25 * if_score + 0.50 * rf_score + 0.25 * ae_score

    try:
        auc = float(roc_auc_score(y_test, ens_score))
    except Exception:
        auc = float("nan")
    return {
        "name":      "Ensemble",
        "precision": float(precision_score(y_test, ens_pred, pos_label=1, zero_division=0)),
        "recall":    float(recall_score(y_test, ens_pred, pos_label=1, zero_division=0)),
        "f1":        float(f1_score(y_test, ens_pred, pos_label=1, zero_division=0)),
        "roc_auc":   auc,
        "n_test":    int(len(y_test)),
    }


def _write_metrics(metrics_by_model: dict, *, dataset: str, attack_rate: float) -> None:
    payload = {
        "trained_at":  datetime.now(timezone.utc).isoformat(),
        "dataset":     dataset,
        "attack_rate": attack_rate,
        "n_features":  NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "models":      metrics_by_model,
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with METRICS_PATH.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    logger.info("metrics_written", path=str(METRICS_PATH))


def main():
    logger.info("training_pipeline_started")
    config.ensure_dirs()

    raw_dir = "data/raw"
    is_synthetic = False
    if not os.path.exists(raw_dir) or not list(Path(raw_dir).glob("*.csv")):
        logger.warning("no_data_found_generating_synthetic", dir=raw_dir)
        _generate_synthetic_data(raw_dir)
        is_synthetic = True

    df = load_cicids(raw_dir)
    X_benign, X_all, y_all = preprocess(df)
    attack_rate = round(float((y_all == 1).mean()) * 100, 2)

    # Stratified 80/20 split
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.2, stratify=y_all, random_state=42
    )
    X_benign_train = X_train[y_train == 0]

    # FAST_TRAIN=1 cuts training cost ~80% so the build fits inside the
    # Hugging Face Spaces free-tier 30-min build budget. Real CICIDS training
    # locally still uses full params by default.
    fast = os.getenv("FAST_TRAIN", "0") in ("1", "true", "yes")
    rf_n  = 80  if fast else 300
    ae_ep = 10  if fast else 50

    metrics: dict = {}

    # Isolation Forest (unsupervised - train on benign only)
    logger.info("training_isolation_forest", fast=fast)
    if_model = IFModel(contamination=0.05, n_estimators=80 if fast else 200)
    if_model.fit(X_benign_train)
    metrics["isolation_forest"] = evaluate_model(if_model, X_test, y_test, "Isolation Forest")
    if_model.save()

    # Random Forest (supervised)
    logger.info("training_random_forest", n_estimators=rf_n)
    rf_model = RFModel(n_estimators=rf_n)
    rf_model.fit(X_train, y_train)
    metrics["random_forest"] = evaluate_model(rf_model, X_test, y_test, "Random Forest")
    rf_model.save()

    # Autoencoder (unsupervised - train on benign only)
    logger.info("training_autoencoder", epochs=ae_ep)
    ae_model = AutoencoderModel(input_dim=NUM_FEATURES, epochs=ae_ep)
    ae_model.fit(X_benign_train)
    metrics["autoencoder"] = evaluate_model(ae_model, X_test, y_test, "Autoencoder")
    ae_model.save()

    metrics["ensemble"] = _ensemble_metrics(if_model, rf_model, ae_model, X_test, y_test)

    dataset = "synthetic (sklearn.make_classification)" if is_synthetic else "CICIDS2017"
    _write_metrics(metrics, dataset=dataset, attack_rate=attack_rate)

    logger.info("training_pipeline_complete")


def _generate_synthetic_data(output_dir: str):
    """
    Generate synthetic training data when CICIDS2017 is not available.
    Suitable for testing the pipeline; not for production model quality.
    """
    import warnings; warnings.filterwarnings("ignore")
    from sklearn.datasets import make_classification
    # 5k samples in fast mode (build-time on Spaces), 50k otherwise.
    fast = os.getenv("FAST_TRAIN", "0") in ("1", "true", "yes")
    X, y = make_classification(
        n_samples=5000 if fast else 50000,
        n_features=NUM_FEATURES,
        n_informative=18, n_redundant=4,
        weights=[0.80, 0.20], random_state=42
    )
    X = np.clip(X, 0, None)    # Features must be non-negative
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["Label"] = np.where(y == 1, "DDoS", "BENIGN")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "synthetic_train.csv")
    df.to_csv(out_path, index=False)
    logger.info("synthetic_data_generated", path=out_path, rows=len(df))


if __name__ == "__main__":
    main()
