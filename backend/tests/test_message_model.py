"""Automated tests for SMS ML Model Training, Loading & Inference."""

import json
from pathlib import Path
import tempfile
from fastapi.testclient import TestClient
import joblib
import pytest

from backend.app.main import app
from backend.app.schemas.common import UnifiedRiskClassification
from backend.app.services.message_model_loader import (
    MessageModelLoader,
    get_message_model_loader,
)
from backend.app.services.message_service import MessageAnalysisService

client = TestClient(app)

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODEL_DIR / "message_model.joblib"
METADATA_PATH = MODEL_DIR / "message_model_metadata.json"


def test_model_artifact_and_metadata_exist():
    """Verify serialized model bundle and metadata JSON exist on disk."""
    assert MODEL_PATH.exists(), f"Model file missing: {MODEL_PATH}"
    assert METADATA_PATH.exists(), f"Metadata file missing: {METADATA_PATH}"

    # Verify bundle structure
    bundle = joblib.load(MODEL_PATH)
    assert isinstance(bundle, dict)
    assert "pipeline" in bundle
    assert "model_name" in bundle
    assert "version" in bundle
    assert "decision_threshold" in bundle

    pipeline = bundle["pipeline"]
    assert hasattr(pipeline, "predict_proba")


def test_model_metadata_content():
    """Verify metadata records lineage, hyperparameters, and test metrics."""
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["model_name"] == "LogisticRegression_TFIDF_v1"
    assert meta["version"] == "1.0.0"
    assert meta["training_data"]["sample_count"] == 4128
    assert meta["training_data"]["spam_count"] == 514
    assert meta["hyperparameters"]["classifier"]["C"] == 5.0
    assert meta["hyperparameters"]["classifier"]["class_weight"] == "balanced"

    # Verify test metrics meet baselines
    assert meta["test_metrics"]["accuracy"] > 0.95
    assert meta["test_metrics"]["spam"]["precision"] > 0.85
    assert meta["test_metrics"]["spam"]["recall"] > 0.85
    assert meta["test_metrics"]["macro_f1"] > 0.90


def test_model_loader_singleton_and_inference():
    """Verify MessageModelLoader loads successfully and predicts correctly."""
    loader = get_message_model_loader()
    assert loader.is_available is True
    assert loader.error_reason is None

    # Test obvious spam
    spam_sample = "WINNER! You have won a 1000 cash prize or a guaranteed award! Call 08712345678 now to claim."
    pred_spam = loader.predict(spam_sample)
    assert pred_spam is not None
    assert pred_spam.is_scam is True
    assert pred_spam.confidence >= 0.70
    assert pred_spam.model_name == "LogisticRegression_TFIDF_v1"

    # Test obvious legitimate message
    ham_sample = "Hey, are you free for dinner tonight at 7? Let me know when you get home."
    pred_ham = loader.predict(ham_sample)
    assert pred_ham is not None
    assert pred_ham.is_scam is False
    assert pred_ham.confidence >= 0.70


def test_inference_deterministic():
    """Verify repeated inference on identical text produces deterministic probabilities."""
    loader = get_message_model_loader()
    sample = "URGENT: Your account verification is required. Please call back immediately."

    pred_1 = loader.predict(sample)
    pred_2 = loader.predict(sample)

    assert pred_1 is not None and pred_2 is not None
    assert pred_1.is_scam == pred_2.is_scam
    assert pred_1.confidence == pred_2.confidence


def test_missing_model_artifact_fallback():
    """Verify that if model file is missing, service gracefully falls back to UNABLE TO VERIFY."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        non_existent_path = Path(tmp_dir) / "missing_model.joblib"
        loader = MessageModelLoader(model_path=str(non_existent_path))

        assert loader.is_available is False
        assert loader.predict("Any message") is None

        # Test service with this missing loader
        service = MessageAnalysisService(model_loader=loader)
        response = service.analyze_message("Urgent notice: Claim your reward now!")

        assert response.classification == UnifiedRiskClassification.UNABLE_TO_VERIFY
        assert response.status == "MODEL_UNAVAILABLE"
        assert response.model_prediction is None
        assert any("Model status" in e for e in response.evidence)


def test_corrupt_model_artifact_fallback():
    """Verify that a corrupted model file does not crash the app and triggers fallback."""
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp_file:
        tmp_file.write(b"CORRUPTED_NOT_A_VALID_JOBLIB_FILE_BYTES_123456")
        corrupt_path = tmp_file.name

    try:
        loader = MessageModelLoader(model_path=corrupt_path)
        assert loader.is_available is False
        assert loader.predict("Any message") is None

        service = MessageAnalysisService(model_loader=loader)
        response = service.analyze_message("Hello world")

        assert response.classification == UnifiedRiskClassification.UNABLE_TO_VERIFY
        assert response.status == "MODEL_UNAVAILABLE"
        assert response.model_prediction is None
    finally:
        Path(corrupt_path).unlink(missing_ok=True)


def test_api_analyze_message_scam_detection():
    """Verify POST /analyze-message detects scam message and returns HIGH RISK / MEDIUM RISK."""
    payload = {
        "message_text": "URGENT! You have won £1,000 cash prize! Text CLAIM to 87121 or call 09061743811 now to collect."
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] in {"HIGH RISK", "MEDIUM RISK"}
    assert data["status"] in {"ANALYSIS_ACTIVE", "STAGE_3_ANALYSIS_ACTIVE"}
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["is_scam"] is True
    assert data["model_prediction"]["confidence"] > 0.5
    assert len(data["evidence"]) >= 2
    assert len(data["recommendations"]) >= 1


def test_api_analyze_message_legitimate_detection():
    """Verify POST /analyze-message detects benign message and returns LOW RISK with disclaimer."""
    payload = {
        "message_text": "Hi Mom, I arrived safely at the train station. See you soon!"
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["classification"] == "LOW RISK"
    assert data["status"] in {"ANALYSIS_ACTIVE", "STAGE_3_ANALYSIS_ACTIVE"}
    assert data["model_prediction"] is not None
    assert data["model_prediction"]["is_scam"] is False
    assert any("LOW RISK is not an absolute guarantee of safety" in r for r in data["recommendations"])


def test_api_empty_or_whitespace_rejected():
    """Verify POST /analyze-message rejects empty and whitespace-only payloads with 422."""
    res1 = client.post("/analyze-message", json={"message_text": ""})
    assert res1.status_code == 422

    res2 = client.post("/analyze-message", json={"message_text": "   "})
    assert res2.status_code == 422
