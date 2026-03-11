"""
ML Training Pipeline.
Ingests CICIDS2017 CSVs, engineers features, trains all three models,
evaluates on a held-out test set, and serialises to disk.

Usage:
    python -m src.ml.train
    docker compose --profile train up ids-trainer
"""
import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from src.ml.isolation_forest import IFModel
from src.ml.random_forest import RFModel
from src.ml.autoencoder import AutoencoderModel
from src.nids.feature_extractor import FEATURE_NAMES, NUM_FEATURES
from src.utils.logger import get_logger
from src.utils.config import config

logger = get_logger(__name__)

# CICIDS2017 column mappings (columns vary slightly between files)
CICIDS_LABEL_COL = "Label"
CICIDS_BENIGN_LABEL = "BENIGN"

# Subset of CICIDS2017 columns mapped to our feature schema
# (We engineer flows ourselves from PCAP but CICIDS provides pre-extracted flows)
CICIDS_FEATURE_COLS = [
    " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    " Fwd Packet Length Max", " Fwd Packet Length Min",
    " Flow Duration", " Flow Bytes/s", " Flow Packets/s",
    " Fwd Packets/s", " Bwd Packets/s",
    " SYN Flag Count", " FIN Flag Count", " RST Flag Count",
    " Destination Port",
]


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


def preprocess(df: pd.DataFrame) -> tuple:
    """
    Clean, engineer features, and create binary labels.
    Returns (X_benign, X_all, y_all).
    """
    # Drop rows with inf / NaN
    df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    df.dropna(subset=[CICIDS_LABEL_COL], inplace=True)
    df.fillna(0, inplace=True)

    # Binary label
    df["binary_label"] = (df[CICIDS_LABEL_COL] != CICIDS_BENIGN_LABEL).astype(int)

    # Feature engineering: map CICIDS columns to our schema
    available = [c for c in CICIDS_FEATURE_COLS if c in df.columns]
    X_raw = df[available].copy().fillna(0)

    # Pad or truncate to NUM_FEATURES
    X = np.zeros((len(X_raw), NUM_FEATURES), dtype=np.float32)
    n_cols = min(len(available), NUM_FEATURES)
    X[:, :n_cols] = X_raw.values[:, :n_cols]

    # Clip extreme values
    X = np.clip(X, 0, 1e9)

    y = df["binary_label"].values.astype(int)
    X_benign = X[y == 0]

    attack_rate = round(y.mean() * 100, 2)
    logger.info("preprocessing_complete", total=len(X), attack_rate=f"{attack_rate}%")

    return X_benign, X, y


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray, name: str):
    """Print classification metrics."""
    preds = np.array([model.predict(x) for x in X_test])
    scores = np.array([model.score(x) for x in X_test])
    print(f"\n{'='*50}")
    print(f"Model: {name}")
    print(classification_report(y_test, preds, target_names=["BENIGN", "ATTACK"]))
    try:
        auc = roc_auc_score(y_test, scores)
        print(f"ROC-AUC: {auc:.4f}")
    except Exception:
        pass


def main():
    logger.info("training_pipeline_started")
    config.ensure_dirs()

    raw_dir = "data/raw"
    if not os.path.exists(raw_dir) or not list(Path(raw_dir).glob("*.csv")):
        logger.warning("no_data_found_generating_synthetic", dir=raw_dir)
        _generate_synthetic_data(raw_dir)

    df = load_cicids(raw_dir)
    X_benign, X_all, y_all = preprocess(df)

    # Stratified 80/20 split
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.2, stratify=y_all, random_state=42
    )
    X_benign_train = X_train[y_train == 0]

    # ── Isolation Forest (unsupervised — train on benign only) ──────────────
    logger.info("training_isolation_forest")
    if_model = IFModel(contamination=0.05)
    if_model.fit(X_benign_train)
    evaluate_model(if_model, X_test, y_test, "Isolation Forest")
    if_model.save()

    # ── Random Forest (supervised) ──────────────────────────────────────────
    logger.info("training_random_forest")
    rf_model = RFModel(n_estimators=300)
    rf_model.fit(X_train, y_train)
    evaluate_model(rf_model, X_test, y_test, "Random Forest")
    rf_model.save()

    # ── Autoencoder (unsupervised — train on benign only) ───────────────────
    logger.info("training_autoencoder")
    ae_model = AutoencoderModel(input_dim=NUM_FEATURES, epochs=50)
    ae_model.fit(X_benign_train)
    evaluate_model(ae_model, X_test, y_test, "Autoencoder")
    ae_model.save()

    logger.info("training_pipeline_complete")


def _generate_synthetic_data(output_dir: str):
    """
    Generate synthetic training data when CICIDS2017 is not available.
    Suitable for testing the pipeline; not for production model quality.
    """
    import warnings; warnings.filterwarnings("ignore")
    from sklearn.datasets import make_classification
    X, y = make_classification(
        n_samples=50000, n_features=NUM_FEATURES,
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
