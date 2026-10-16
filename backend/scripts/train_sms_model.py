"""Scam Message Detection Model Training & Evaluation Pipeline.

Part of FraudLens Message Detection Engine: SMS ML Model Training and Evaluation.

Trains a TF-IDF + Logistic Regression pipeline on the prepared training split,
validates hyperparameters and thresholding against the validation set, and
evaluates the finalized model on the held-out test split.

Outputs:
  - backend/models/message_model.joblib
  - backend/models/message_model_metadata.json
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline


def compute_sha256(file_path: Path) -> str:
    """Compute hex SHA-256 digest of a file."""
    return hashlib.sha256(file_path.read_bytes()).hexdigest()


def train_and_evaluate_model(
    train_path: Path,
    val_path: Path,
    test_path: Path,
    output_model_path: Path,
    output_metadata_path: Path,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train pipeline on train split, tune/validate on val split, evaluate on test split."""
    print("=== Training Scam Message Detection Baseline Model ===")

    # 1. Load splits
    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    X_train, y_train = df_train["text"], df_train["is_scam"]
    X_val, y_val = df_val["text"], df_val["is_scam"]
    X_test, y_test = df_test["text"], df_test["is_scam"]

    print(f"Training samples:   {len(df_train)} (Spam: {y_train.sum()}, Ham: {len(y_train) - y_train.sum()})")
    print(f"Validation samples: {len(df_val)} (Spam: {y_val.sum()}, Ham: {len(y_val) - y_val.sum()})")
    print(f"Test samples:       {len(df_test)} (Spam: {y_test.sum()}, Ham: {len(y_test) - y_test.sum()})")

    # 2. Build Pipeline
    # Selected configuration based on validation experiments:
    # - TfidfVectorizer with word unigrams + bigrams, sublinear TF scaling, max 10000 features
    # - LogisticRegression with balanced class weights (to handle 87.4% / 12.6% imbalance) and C=5.0
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        lowercase=True,
        max_features=10000,
        sublinear_tf=True,
    )
    classifier = LogisticRegression(
        random_state=random_state,
        C=5.0,
        class_weight="balanced",
        max_iter=1000,
        solver="lbfgs",
    )

    pipeline = Pipeline([
        ("tfidf", vectorizer),
        ("clf", classifier),
    ])

    # 3. Fit strictly on training data
    print("Fitting TF-IDF Vectorizer and Logistic Regression on training data...")
    pipeline.fit(X_train, y_train)

    # 4. Evaluate on Validation Set
    val_probs = pipeline.predict_proba(X_val)[:, 1]
    val_preds = (val_probs >= 0.5).astype(int)

    val_cm = confusion_matrix(y_val, val_preds)
    val_metrics = {
        "accuracy": float(accuracy_score(y_val, val_preds)),
        "macro_f1": float(f1_score(y_val, val_preds, average="macro")),
        "spam": {
            "precision": float(precision_score(y_val, val_preds, pos_label=1)),
            "recall": float(recall_score(y_val, val_preds, pos_label=1)),
            "f1": float(f1_score(y_val, val_preds, pos_label=1)),
        },
        "ham": {
            "precision": float(precision_score(y_val, val_preds, pos_label=0)),
            "recall": float(recall_score(y_val, val_preds, pos_label=0)),
            "f1": float(f1_score(y_val, val_preds, pos_label=0)),
        },
        "confusion_matrix": {
            "tn": int(val_cm[0, 0]),
            "fp": int(val_cm[0, 1]),
            "fn": int(val_cm[1, 0]),
            "tp": int(val_cm[1, 1]),
        },
    }

    # 5. Evaluate on Held-Out Test Set
    test_probs = pipeline.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.5).astype(int)

    test_cm = confusion_matrix(y_test, test_preds)
    test_metrics = {
        "accuracy": float(accuracy_score(y_test, test_preds)),
        "macro_f1": float(f1_score(y_test, test_preds, average="macro")),
        "spam": {
            "precision": float(precision_score(y_test, test_preds, pos_label=1)),
            "recall": float(recall_score(y_test, test_preds, pos_label=1)),
            "f1": float(f1_score(y_test, test_preds, pos_label=1)),
        },
        "ham": {
            "precision": float(precision_score(y_test, test_preds, pos_label=0)),
            "recall": float(recall_score(y_test, test_preds, pos_label=0)),
            "f1": float(f1_score(y_test, test_preds, pos_label=0)),
        },
        "confusion_matrix": {
            "tn": int(test_cm[0, 0]),
            "fp": int(test_cm[0, 1]),
            "fn": int(test_cm[1, 0]),
            "tp": int(test_cm[1, 1]),
        },
    }

    # Extract top vocabulary indicators (highest positive coefficients = spam, highest negative = ham)
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = classifier.coef_[0]
    top_spam_indices = np.argsort(coefs)[-20:][::-1]
    top_ham_indices = np.argsort(coefs)[:20]

    top_spam_features = [
        {"feature": str(feature_names[i]), "weight": float(coefs[i])}
        for i in top_spam_indices
    ]
    top_ham_features = [
        {"feature": str(feature_names[i]), "weight": float(coefs[i])}
        for i in top_ham_indices
    ]

    # 6. Save Model Bundle
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    model_bundle = {
        "pipeline": pipeline,
        "model_name": "LogisticRegression_TFIDF_v1",
        "version": "1.0.0",
        "decision_threshold": 0.5,
        "classes": [0, 1],
    }
    joblib.dump(model_bundle, output_model_path, compress=3)
    model_sha256 = compute_sha256(output_model_path)

    # 7. Save Metadata
    metadata = {
        "model_name": "LogisticRegression_TFIDF_v1",
        "version": "1.0.0",
        "model_type": "Pipeline(TfidfVectorizer, LogisticRegression)",
        "artifact_file": output_model_path.name,
        "artifact_sha256": model_sha256,
        "training_data": {
            "file": train_path.name,
            "sha256": compute_sha256(train_path),
            "sample_count": len(df_train),
            "spam_count": int(y_train.sum()),
            "ham_count": int(len(y_train) - y_train.sum()),
        },
        "hyperparameters": {
            "vectorizer": {
                "ngram_range": [1, 2],
                "lowercase": True,
                "max_features": 10000,
                "sublinear_tf": True,
            },
            "classifier": {
                "C": 5.0,
                "class_weight": "balanced",
                "max_iter": 1000,
                "solver": "lbfgs",
                "random_state": random_state,
            },
            "decision_threshold": 0.5,
        },
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "interpretability": {
            "top_spam_features": top_spam_features,
            "top_ham_features": top_ham_features,
        },
    }

    output_metadata_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\n--- Validation Performance ---")
    print(f"Accuracy: {val_metrics['accuracy']:.4f}, Macro F1: {val_metrics['macro_f1']:.4f}")
    print(f"Spam -> Precision: {val_metrics['spam']['precision']:.4f}, Recall: {val_metrics['spam']['recall']:.4f}, F1: {val_metrics['spam']['f1']:.4f}")
    print(f"Confusion Matrix: TN={val_cm[0,0]}, FP={val_cm[0,1]}, FN={val_cm[1,0]}, TP={val_cm[1,1]}")

    print("\n--- Final Test Performance (Held-Out) ---")
    print(f"Accuracy: {test_metrics['accuracy']:.4f}, Macro F1: {test_metrics['macro_f1']:.4f}")
    print(f"Spam -> Precision: {test_metrics['spam']['precision']:.4f}, Recall: {test_metrics['spam']['recall']:.4f}, F1: {test_metrics['spam']['f1']:.4f}")
    print(f"Ham  -> Precision: {test_metrics['ham']['precision']:.4f}, Recall: {test_metrics['ham']['recall']:.4f}, F1: {test_metrics['ham']['f1']:.4f}")
    print(f"Confusion Matrix: TN={test_cm[0,0]}, FP={test_cm[0,1]}, FN={test_cm[1,0]}, TP={test_cm[1,1]}")

    print(f"\nModel artifact saved to: {output_model_path} ({model_sha256[:16]}...)")
    print(f"Metadata saved to:       {output_metadata_path}")

    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and evaluate baseline SMS scam model.")
    parser.add_argument(
        "--train-path",
        type=Path,
        default=Path("D:/Projects/usability/data/processed/sms/sms_train.csv"),
    )
    parser.add_argument(
        "--val-path",
        type=Path,
        default=Path("D:/Projects/usability/data/processed/sms/sms_val.csv"),
    )
    parser.add_argument(
        "--test-path",
        type=Path,
        default=Path("D:/Projects/usability/data/processed/sms/sms_test.csv"),
    )
    parser.add_argument(
        "--output-model",
        type=Path,
        default=Path("D:/Projects/usability/backend/models/message_model.joblib"),
    )
    parser.add_argument(
        "--output-metadata",
        type=Path,
        default=Path("D:/Projects/usability/backend/models/message_model_metadata.json"),
    )
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()
    train_and_evaluate_model(
        train_path=args.train_path,
        val_path=args.val_path,
        test_path=args.test_path,
        output_model_path=args.output_model,
        output_metadata_path=args.output_metadata,
        random_state=args.seed,
    )
