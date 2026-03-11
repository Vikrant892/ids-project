"""
Autoencoder — Deep Anomaly Detector.
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
    """Training and inference wrapper for the autoencoder."""

    def __init__(self, input_dim: int = NUM_FEATURES,
                 lr: float = 1e-3, epochs: int = 50, batch_size: int = 256):
        self.input_dim = input_dim
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.net = _AutoencoderNet(input_dim).to(DEVICE)
        self._threshold = 0.5    # MSE threshold; calibrated after training
        self._mse_mean = 0.0
        self._mse_std = 1.0
        self._fitted = False

    def fit(self, X: np.ndarray):
        """
        Train on benign-only matrix X of shape (N, input_dim).
        Calibrates the MSE threshold at mean + 3*std of training reconstruction errors.
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

        # Calibrate threshold on training data
        errors = self._compute_errors(X)
        self._mse_mean = float(np.mean(errors))
        self._mse_std = float(np.std(errors))
        self._threshold = self._mse_mean + 3 * self._mse_std
        self._fitted = True
        logger.info("autoencoder_trained", samples=X.shape[0],
                    mse_mean=round(self._mse_mean, 6),
                    threshold=round(self._threshold, 6))

    def _compute_errors(self, X: np.ndarray) -> np.ndarray:
        self.net.eval()
        with torch.no_grad():
            t = torch.FloatTensor(X).to(DEVICE)
            recon = self.net(t)
            errors = ((t - recon) ** 2).mean(dim=1).cpu().numpy()
        return errors

    def score(self, x: np.ndarray) -> float:
        """Normalised anomaly score in [0,1]."""
        if not self._fitted:
            raise RuntimeError("Model not fitted.")
        err = self._compute_errors(x.reshape(1, -1))[0]
        normalised = (err - self._mse_mean) / (self._mse_std + 1e-8)
        return float(np.clip(normalised / 6.0 + 0.5, 0.0, 1.0))

    def predict(self, x: np.ndarray) -> int:
        return int(self.score(x) >= config.AUTOENCODER_THRESHOLD)

    def save(self):
        Path(config.MODEL_DIR).mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict":  self.net.state_dict(),
            "threshold":   self._threshold,
            "mse_mean":    self._mse_mean,
            "mse_std":     self._mse_std,
            "input_dim":   self.input_dim,
        }, config.AE_MODEL_PATH)
        logger.info("autoencoder_saved", path=config.AE_MODEL_PATH)

    def load(self):
        ckpt = torch.load(config.AE_MODEL_PATH, map_location=DEVICE)
        self.net = _AutoencoderNet(ckpt["input_dim"]).to(DEVICE)
        self.net.load_state_dict(ckpt["state_dict"])
        self._threshold = ckpt["threshold"]
        self._mse_mean  = ckpt["mse_mean"]
        self._mse_std   = ckpt["mse_std"]
        self._fitted = True
        logger.info("autoencoder_loaded", path=config.AE_MODEL_PATH)
