"""Safe model loading and inference utility for the FraudLens URL Phishing Detector.

Loads the Random Forest artifact and metadata, caching it as a process-level singleton.
Provides safe error handling on missing or corrupt files, never crashing the application.
"""

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from backend.app.services.url_features import (
    FEATURE_NAMES,
    extract_url_feature_dict,
    extract_url_feature_vector,
)

logger = logging.getLogger(__name__)

_backend_dir = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODEL_PATH = _backend_dir / "models" / "url_model.joblib"
DEFAULT_METADATA_PATH = _backend_dir / "models" / "url_model_metadata.json"


@dataclass
class URLModelInferenceResult:
    """Inference output from URL phishing model."""

    is_phishing: bool
    probability: float
    decision_threshold: float
    model_name: str
    feature_count: int
    top_contributing_features: List[Dict[str, Any]]


class URLModelLoader:
    """Singleton loader for URL model with lazy caching and resilient fallback."""

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        metadata_path: Path = DEFAULT_METADATA_PATH,
    ):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self._model = None
        self._metadata: Optional[Dict[str, Any]] = None
        self._load_attempted = False
        self._load_successful = False

    def load_model(self) -> bool:
        """Attempt to load the model artifact and metadata safely."""
        self._load_attempted = True

        if not self.model_path.exists():
            logger.warning("URL model artifact not found at %s. Falling back.", self.model_path)
            self._load_successful = False
            return False

        try:
            self._model = joblib.load(self.model_path)
            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = None
            self._load_successful = True
            logger.info("URL phishing model successfully loaded from %s", self.model_path)
            return True
        except Exception as e:
            logger.error("Failed to load URL model artifact: %s", e)
            self._model = None
            self._metadata = None
            self._load_successful = False
            return False

    @property
    def is_available(self) -> bool:
        """Check if model is currently loaded and available for inference."""
        if not self._load_attempted:
            self.load_model()
        return self._load_successful and self._model is not None

    @property
    def metadata(self) -> Optional[Dict[str, Any]]:
        if not self._load_attempted:
            self.load_model()
        return self._metadata

    def predict(self, url: str) -> Optional[URLModelInferenceResult]:
        """Perform deterministic inference on a URL string.

        Returns None if model is unavailable or inference fails.
        """
        if not self.is_available:
            return None

        try:
            feature_vector = extract_url_feature_vector(url)
            X = np.array([feature_vector], dtype=np.float32)

            # Predict probability of class 1 (phishing)
            probs = self._model.predict_proba(X)[0]
            phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

            # Retrieve thresholds
            thresholds = self._metadata.get("thresholds", {}) if self._metadata else {}
            decision_threshold = float(thresholds.get("decision_threshold", 0.50))

            is_phishing = bool(phishing_prob >= decision_threshold)

            # Extract top contributing non-zero features for explainability
            feature_dict = extract_url_feature_dict(url)
            active_features = [
                {"name": name, "value": val}
                for name, val in feature_dict.items()
                if val > 0.0 and name not in ("is_http", "count_letters")
            ]

            return URLModelInferenceResult(
                is_phishing=is_phishing,
                probability=round(phishing_prob, 4),
                decision_threshold=decision_threshold,
                model_name=self._metadata.get("model_name", "RandomForest_URL_v1") if self._metadata else "RandomForest_URL_v1",
                feature_count=len(FEATURE_NAMES),
                top_contributing_features=active_features[:8],
            )
        except Exception as e:
            logger.error("URL model inference failed on '%s': %s", url, e)
            return None


_global_url_model_loader: Optional[URLModelLoader] = None


def get_url_model_loader() -> URLModelLoader:
    """Dependency injector for singleton URLModelLoader."""
    global _global_url_model_loader
    if _global_url_model_loader is None:
        _global_url_model_loader = URLModelLoader()
    return _global_url_model_loader
