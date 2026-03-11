"""
Random Forest Classifier — Supervised ML Model.
Trained on CICIDS2017 labelled network flow dataset.
Outputs a confidence probability for attack vs benign.

Attack classes mapped from CICIDS2017:
  BENIGN, DoS, DDoS, PortScan, Brute Force, Web Attack, Infiltration, Botnet
  → Binary: 0=BENIGN, 1=ATTACK
"""
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

ATTACK_LABEL = 1
BENIGN_LABEL = 0


class RFModel:
    """Wraps sklearn RandomForestClassifier with IDS-specific helpers."""

    def __init__(self, n_estimators: int = 300, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=None,
            min_samples_split=2,
            class_weight="balanced",   # Handle class imbalance
            random_state=random_state,
            n_jobs=-1,
        )
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        """
        Train classifier.
        X: (N, num_features), y: binary array (0=benign, 1=attack).
        """
        self.model.fit(X, y)
        self._fitted = True
        n_attack = int(np.sum(y))
        n_benign = len(y) - n_attack
        logger.info("random_forest_trained", samples=len(y),
                    benign=n_benign, attack=n_attack)

    def score(self, x: np.ndarray) -> float:
        """
        Returns probability that the sample is an attack.
        Range: [0, 1]. Threshold applied in ensemble.
        """
        if not self._fitted:
            raise RuntimeError("Model not fitted.")
        proba = self.model.predict_proba(x.reshape(1, -1))[0]
        return float(proba[ATTACK_LABEL])

    def predict(self, x: np.ndarray) -> int:
        """Binary prediction using configured confidence threshold."""
        return int(self.score(x) >= config.RF_CONFIDENCE_THRESHOLD)

    def feature_importance(self) -> dict:
        """Return feature importance dict for dashboard display."""
        from src.nids.feature_extractor import FEATURE_NAMES
        return dict(zip(FEATURE_NAMES, self.model.feature_importances_.tolist()))

    def save(self):
        Path(config.MODEL_DIR).mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, config.RF_MODEL_PATH)
        logger.info("random_forest_saved", path=config.RF_MODEL_PATH)

    def load(self):
        self.model = joblib.load(config.RF_MODEL_PATH)
        self._fitted = True
        logger.info("random_forest_loaded", path=config.RF_MODEL_PATH)
