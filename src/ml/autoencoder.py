"""
Autoencoder - Deep Anomaly Detector.
Trained on benign traffic only. Reconstruction error on attack traffic
is significantly higher than benign, enabling detection.

Architecture: Encoder → bottleneck latent space → Decoder
Loss: MSE reconstruction loss
Anomaly score = reconstruction error normalised to [0,1]
"""
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from src.utils.config import config
from src.nids.feature_extractor import NUM_FEATURES
from src.utils.logger import get_logger

logger = get_logger(__name__)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class _AutoencoderNet(nn.Module):
    """
    3-layer encoder, 3-layer decoder with ReLU activations.
    Bottleneck is 1/4 of input size.
    """

    def __init__(self, input_dim: int):
        super().__init__()
        h1 = max(input_dim * 2, 64)
        h2 = max(input_dim, 32)
        bottleneck = max(input_dim // 4, 8)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1),
            nn.ReLU(),
            nn.BatchNorm1d(h1),
            nn.Linear(h1, h2),
            nn.ReLU(),
            nn.BatchNorm1d(h2),
            nn.Linear(h2, bottleneck),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, h2),
            nn.ReLU(),
            nn.BatchNorm1d(h2),
            nn.Linear(h2, h1),
            nn.ReLU(),
            nn.BatchNorm1d(h1),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        x_hat = self.decoder(z)
        return x_hat


class AutoencoderModel:
    """
    Training and inference wrapper for the autoencoder.

    Threshold model:
      - During fit(), the reconstruction-error threshold is calibrated as a
        percentile of training errors (default 95th). This threshold lives in
        raw MSE space and is the SOLE source of the binary detection rule.
      - score(x) returns a smooth confidence in [0, 1] used by the ensemble
        for weighted scoring; it is independent of the binary threshold.
      - The previous static AUTOENCODER_THRESHOLD env var (a normalised-score
        cutoff at 0.85) has been removed because the calibrated threshold was
        being computed and saved but never consulted.
    """

    def __init__(self, input_dim: int = NUM_FEATURES,
                 lr: float = 1e-3, epochs: int = 50, batch_size: int = 256,
                 threshold_percentile: float = None):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.net = _AutoencoderNet(input_dim).to(DEVICE)
        self._threshold = 0.0
        self._threshold_percentile = (
            threshold_percentile
            if threshold_percentile is not None
            else float(config.AUTOENCODER_THRESHOLD_PERCENTILE)
        )
        self._mse_mean = 0.0
        self._mse_std = 1.0
        self._fitted = False

    def fit(self, X: np.ndarray):
        """
        Train on benign-only matrix X of shape (N, input_dim).
        Calibrates the MSE threshold at the configured percentile of training
        reconstruction errors.
        """
        dataset = torch.FloatTensor(X).to(DEVICE)
        loader = torch.utils.data.DataLoader(
            dataset, batch_size=self.batch_size, shuffle=True
        )
        optimiser = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        criterion = nn.MSELoss()
        self.net.train()

        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for batch in loader:
                optimiser.zero_grad()
                recon = self.net(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimiser.step()
                epoch_loss += loss.item()
            avg = epoch_loss / len(loader)
            if (epoch + 1) % 10 == 0:
                logger.info("ae_epoch", epoch=epoch + 1, loss=round(avg, 6))

        # Calibrate threshold from training-error distribution
        errors = self._compute_errors(X)
        self._mse_mean = float(np.mean(errors))
        self._mse_std = float(np.std(errors))
        self._threshold = float(np.percentile(errors, self._threshold_percentile))
        self._fitted = True
        logger.info(
            "autoencoder_trained",
            samples=X.shape[0],
            mse_mean=round(self._mse_mean, 6),
            mse_std=round(self._mse_std, 6),
            threshold=round(self._threshold, 6),
            percentile=self._threshold_percentile,
        )

    def _compute_errors(self, X: np.ndarray) -> np.ndarray:
        self.net.eval()
        with torch.no_grad():
            t = torch.FloatTensor(X).to(DEVICE)
            recon = self.net(t)
            errors = ((t - recon) ** 2).mean(dim=1).cpu().numpy()
        return errors

    def score(self, x: np.ndarray) -> float:
        """
        Smooth anomaly confidence in [0, 1] for ensemble weighting.
        Centred so that an error equal to the training mean returns ~0.5
        and an error well above threshold saturates near 1.0.
        """
        if not self._fitted:
            raise RuntimeError("Model not fitted.")
        err = self._compute_errors(x.reshape(1, -1))[0]
        normalised = (err - self._mse_mean) / (self._mse_std + 1e-8)
        return float(np.clip(normalised / 6.0 + 0.5, 0.0, 1.0))

    def predict(self, x: np.ndarray) -> int:
        """Binary label using the calibrated raw-error threshold."""
        if not self._fitted:
            raise RuntimeError("Model not fitted.")
        err = self._compute_errors(x.reshape(1, -1))[0]
        return int(err >= self._threshold)

    def save(self):
        Path(config.MODEL_DIR).mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict":            self.net.state_dict(),
            "threshold":             self._threshold,
            "threshold_percentile":  self._threshold_percentile,
            "mse_mean":              self._mse_mean,
            "mse_std":               self._mse_std,
            "input_dim":             self.input_dim,
            "schema_version":        2,
        }, config.AE_MODEL_PATH)
        logger.info("autoencoder_saved", path=config.AE_MODEL_PATH)

    def load(self):
        # weights_only=False is required because we persist scalar metadata
        # alongside the state_dict; the file is produced by our own train job.
        ckpt = torch.load(config.AE_MODEL_PATH, map_location=DEVICE, weights_only=False)
        if ckpt.get("input_dim", NUM_FEATURES) != NUM_FEATURES:
            raise RuntimeError(
                f"Autoencoder checkpoint expects input_dim={ckpt.get('input_dim')} "
                f"but feature schema has NUM_FEATURES={NUM_FEATURES} - retrain."
            )
        self.net = _AutoencoderNet(ckpt["input_dim"]).to(DEVICE)
        self.net.load_state_dict(ckpt["state_dict"])
        self._threshold = ckpt["threshold"]
        self._threshold_percentile = ckpt.get("threshold_percentile", 95.0)
        self._mse_mean  = ckpt["mse_mean"]
        self._mse_std   = ckpt["mse_std"]
        self._fitted = True
        logger.info(
            "autoencoder_loaded",
            path=config.AE_MODEL_PATH,
            threshold=round(self._threshold, 6),
        )
