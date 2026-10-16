"""Unit and integration tests for URL model artifact, metadata, and loader."""

import json
from pathlib import Path
import pytest

from backend.app.services.url_model_loader import (
    URLModelLoader,
    get_url_model_loader,
)


MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODEL_DIR / "url_model.joblib"
METADATA_PATH = MODEL_DIR / "url_model_metadata.json"


def test_url_model_artifacts_exist():
    """Verify URL model artifact and metadata exist on disk."""
    assert MODEL_PATH.exists(), f"Model artifact missing at {MODEL_PATH}"
    assert METADATA_PATH.exists(), f"Model metadata missing at {METADATA_PATH}"
    assert MODEL_PATH.stat().st_size > 100_000  # Non-trivial model file


def test_url_model_metadata_content():
    """Verify contents and metrics documented in model metadata."""
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["model_name"] == "RandomForest_URL_v1"
    assert meta["model_class"] == "RandomForestClassifier"
    assert meta["random_seed"] == 42
    assert meta["features"]["feature_count"] == 34
    assert len(meta["features"]["feature_names"]) == 34

    # Label mapping
    assert meta["label_mapping"]["0"] == "legitimate"
    assert meta["label_mapping"]["1"] == "phishing"

    # Calibration threshold
    assert "thresholds" in meta
    assert 0.1 <= meta["thresholds"]["decision_threshold"] <= 0.9

    # Test evaluation metrics documented
    test_eval = meta["test_evaluation"]
    assert test_eval["accuracy"] >= 0.90
    assert test_eval["roc_auc"] >= 0.95
    assert test_eval["phishing_class_1"]["precision"] >= 0.70
    assert test_eval["phishing_class_1"]["recall"] >= 0.70

    # Stress test metrics documented
    stress_eval = meta["stress_test_evaluation"]
    assert stress_eval["samples"] == 4672
    assert stress_eval["detection_rate"] >= 0.80
    assert "limitation_note" in stress_eval


def test_url_model_loader_singleton_and_deterministic_inference():
    """Verify singleton loader and reproducible predictions."""
    loader1 = get_url_model_loader()
    loader2 = get_url_model_loader()
    assert loader1 is loader2
    assert loader1.is_available is True

    test_url = "https://secure-login.paypal.com.account-update.xyz/verify.php"
    res1 = loader1.predict(test_url)
    res2 = loader1.predict(test_url)

    assert res1 is not None
    assert res2 is not None
    assert res1.is_phishing == res2.is_phishing
    assert res1.probability == res2.probability
    assert res1.feature_count == 34


def test_url_model_threshold_behavior():
    """Verify threshold boundary correctly separates binary prediction."""
    loader = get_url_model_loader()
    res = loader.predict("https://paypal.com.account-verification-auth.xyz/login.php")
    assert res is not None
    if res.probability >= res.decision_threshold:
        assert res.is_phishing is True
    else:
        assert res.is_phishing is False


def test_missing_model_artifact_graceful_fallback(tmp_path):
    """Verify loader handles missing model files safely without crashing."""
    fake_model_path = tmp_path / "non_existent.joblib"
    loader = URLModelLoader(model_path=fake_model_path, metadata_path=tmp_path / "meta.json")

    assert loader.is_available is False
    assert loader.predict("https://example.com") is None


def test_corrupt_model_artifact_graceful_fallback(tmp_path):
    """Verify loader handles corrupt joblib files safely without crashing."""
    corrupt_path = tmp_path / "corrupt_model.joblib"
    corrupt_path.write_bytes(b"corrupt junk data that is not joblib")

    loader = URLModelLoader(model_path=corrupt_path, metadata_path=tmp_path / "meta.json")
    assert loader.is_available is False
    assert loader.predict("https://example.com") is None
