"""
Ensemble ML Engine.
Combines Isolation Forest + Random Forest + Autoencoder via majority voting
with weighted confidence scoring.

Voting logic:
  - Each model votes: 1 (attack) or 0 (benign)
  - Total votes >= ENSEMBLE_VOTE_THRESHOLD → flag as anomaly
  - Confidence = weighted average of anomaly scores

Weight defaults (adjust based on observed F1 on validation set):
  IF:  0.25  (unsupervised, higher FP rate)
  RF:  0.50  (supervised, highest precision on known attacks)
  AE:  0.25  (reconstruction error, good for novel attacks)
"""
from typing import Optional, Tuple
import numpy as np
from src.ml.isolation_forest import IFModel
from src.ml.random_forest import RFModel
from src.ml.autoencoder import AutoencoderModel
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

MODEL_WEIGHTS = {"if": 0.25, "rf": 0.50, "ae": 0.25}


class EnsembleDetector:
    """
    Loads all three models and provides a unified score interface.
    Falls back gracefully if a model fails (logs warning, continues).
    """

    def __init__(self):
        self.if_model = IFModel()
        self.rf_model = RFModel()
        self.ae_model = AutoencoderModel()
        self._models_loaded = False

    def load_models(self):
        """Load all serialised models from disk."""
        errors = []
        for name, model in [("IF", self.if_model), ("RF", self.rf_model), ("AE", self.ae_model)]:
            try:
                model.load()
            except Exception as e:
                errors.append(name)
                logger.warning(f"model_load_failed", model=name, error=str(e))
        self._models_loaded = True
        if errors:
            logger.warning("some_models_unavailable", models=errors)
        else:
            logger.info("all_models_loaded")

    def predict(self, features: np.ndarray) -> Tuple[int, float, dict]:
        """
        Run ensemble inference on a feature vector.

        Returns:
          - label: 1 (attack) or 0 (benign)
          - confidence: float in [0, 1]
          - details: per-model scores and votes
        """
        scores = {}
        votes = {}

        for name, model, weight_key in [
            ("isolation_forest", self.if_model, "if"),
            ("random_forest",    self.rf_model, "rf"),
            ("autoencoder",      self.ae_model, "ae"),
        ]:
            try:
                score = model.score(features)
                vote  = model.predict(features)
                scores[name] = round(score, 4)
                votes[name]  = vote
            except Exception as e:
                logger.warning("model_inference_error", model=name, error=str(e))
                scores[name] = 0.0
                votes[name]  = 0

        total_votes = sum(votes.values())
        label = int(total_votes >= config.ENSEMBLE_VOTE_THRESHOLD)

        # Weighted confidence
        confidence = (
            MODEL_WEIGHTS["if"] * scores.get("isolation_forest", 0) +
            MODEL_WEIGHTS["rf"] * scores.get("random_forest", 0) +
            MODEL_WEIGHTS["ae"] * scores.get("autoencoder", 0)
        )

        details = {
            "model_scores": scores,
            "model_votes":  votes,
            "total_votes":  total_votes,
        }

        return label, round(confidence, 4), details

    def is_ready(self) -> bool:
        return self._models_loaded
