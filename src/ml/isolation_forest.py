"""
Isolation Forest — Unsupervised Anomaly Detector.
No labelled data required. Useful for zero-day / novel attack detection.
Trained on BENIGN traffic only; anomaly score = how isolated a point is.
"""
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pathlib import Path
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class IFModel:
    """
    Wraps sklearn IsolationForest with fit/score/save/load.
    Contamination = expected fraction of anomalies in training data.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200,
                 random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_features=1.0,
            bootstrap=False,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, X: np.ndarray):
        """
        Train on benign-only feature matrix X of shape (N, num_features).
        StandardScaler is fit here so inference uses the same scaling.
        """
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._fitted = True
        logger.info("isolation_forest_trained", samples=X.shape[0],
                    features=X.shape[1], contamination=self.contamination)

    def score(self, x: np.ndarray) -> float:
        """
        Score a single feature vector.
        Returns anomaly probability in [0, 1]. Higher = more anomalous.
        IsolationForest.decision_function returns negative scores for anomalies;
        we normalise to [0,1].
        """
        if not self._fitted:
            raise RuntimeError("Model not fitted. Call fit() or load() first.")
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        raw = self.model.decision_function(x_scaled)[0]
        # Map from roughly [-0.5, 0.5] to [0, 1], clipped
        normalised = 1.0 - (raw + 0.5)
        return float(np.clip(normalised, 0.0, 1.0))

    def predict(self, x: np.ndarray) -> int:
        """Returns 1 (anomaly) or 0 (normal) based on threshold."""
        return int(self.score(x) >= config.ANOMALY_THRESHOLD)

    def save(self):
        Path(config.MODEL_DIR).mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, config.IF_MODEL_PATH)
        logger.info("isolation_forest_saved", path=config.IF_MODEL_PATH)

    def load(self):
        data = joblib.load(config.IF_MODEL_PATH)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self._fitted = True
        logger.info("isolation_forest_loaded", path=config.IF_MODEL_PATH)
