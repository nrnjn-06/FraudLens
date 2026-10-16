"""Model loading and inference utility for Scam Message Detection.

Part of FraudLens Message Detection Engine: SMS ML Model Inference.

Safely loads the serialized scikit-learn pipeline, caches it in memory,
and handles missing, corrupted, or incompatible artifacts with honest fallback.
Never accepts user-controlled model file paths.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
from backend.app.config import settings
from backend.app.schemas.message import MessageModelPrediction

logger = logging.getLogger(__name__)


class MessageModelLoader:
    """Manages secure loading, caching, and inference for the SMS scam model."""

    def __init__(self, model_path: Optional[str] = None):
        self._configured_path = model_path or settings.MESSAGE_MODEL_PATH
        self._bundle: Optional[Dict[str, Any]] = None
        self._is_loaded: bool = False
        self._error_reason: Optional[str] = None

        # Attempt initial load
        self.load()

    def _resolve_model_path(self) -> Path:
        """Resolve canonical model path relative to project structure."""
        p = Path(self._configured_path)
        if not p.is_absolute():
            # If relative, check against usability project root or backend dir
            project_root = Path(__file__).resolve().parent.parent.parent.parent
            candidate_1 = project_root / p
            candidate_2 = project_root / "usability" / p
            candidate_3 = Path.cwd() / p

            if candidate_1.exists():
                return candidate_1
            if candidate_2.exists():
                return candidate_2
            if candidate_3.exists():
                return candidate_3
            return candidate_1
        return p

    def load(self) -> bool:
        """Load and validate serialized model bundle.

        Catches FileNotFoundError, corrupted files, and incompatible architectures,
        ensuring the application never crashes on bad model artifacts.
        """
        resolved = self._resolve_model_path()
        if not resolved.exists():
            self._is_loaded = False
            self._error_reason = f"Model artifact not found at {resolved}"
            logger.warning(self._error_reason)
            return False

        try:
            bundle = joblib.load(resolved)
            if not isinstance(bundle, dict):
                raise ValueError("Model bundle must be a dictionary containing 'pipeline' and metadata.")

            if "pipeline" not in bundle:
                raise KeyError("Model bundle missing required 'pipeline' key.")

            pipeline = bundle["pipeline"]
            if not hasattr(pipeline, "predict_proba"):
                raise AttributeError("Model pipeline must implement predict_proba.")

            self._bundle = bundle
            self._is_loaded = True
            self._error_reason = None
            logger.info("Successfully loaded message scam model: %s (v%s)", bundle.get("model_name"), bundle.get("version"))
            return True

        except Exception as e:
            self._bundle = None
            self._is_loaded = False
            self._error_reason = f"Failed to load model artifact: {type(e).__name__}: {str(e)}"
            logger.error(self._error_reason)
            return False

    @property
    def is_available(self) -> bool:
        """Indicate whether the model is loaded and ready for inference."""
        return self._is_loaded and self._bundle is not None

    @property
    def error_reason(self) -> Optional[str]:
        """Description of why the model could not be loaded, if any."""
        return self._error_reason

    def predict(self, text: str) -> Optional[MessageModelPrediction]:
        """Execute probabilistic inference on input text string.

        Returns None if model is unavailable or inference fails,
        enabling honest UNABLE TO VERIFY fallback.
        """
        if not self.is_available:
            # Attempt lazy reload once in case artifact was created post-startup
            if not self.load():
                return None

        clean_text = text.strip() if text else ""
        if not clean_text:
            return None

        try:
            pipeline = self._bundle["pipeline"]
            threshold = float(self._bundle.get("decision_threshold", 0.5))
            model_name = str(self._bundle.get("model_name", "LogisticRegression_TFIDF_v1"))

            # Predict probabilities [P(ham), P(spam)]
            probs = pipeline.predict_proba([clean_text])[0]
            prob_ham = float(probs[0])
            prob_spam = float(probs[1])

            is_scam = prob_spam >= threshold
            confidence = prob_spam if is_scam else prob_ham

            return MessageModelPrediction(
                is_scam=is_scam,
                confidence=round(confidence, 4),
                model_name=model_name,
            )
        except Exception as e:
            logger.error("Error during model inference: %s", e)
            return None


# Global singleton instance
_message_model_loader: Optional[MessageModelLoader] = None


def get_message_model_loader() -> MessageModelLoader:
    """Dependency injector / singleton accessor for MessageModelLoader."""
    global _message_model_loader
    if _message_model_loader is None:
        _message_model_loader = MessageModelLoader()
    return _message_model_loader
