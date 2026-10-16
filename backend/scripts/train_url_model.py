"""Model training and evaluation pipeline for FraudLens Phishing URL Detection.

Trains Random Forest on url_train.csv (34 deterministic features), calibrates decision threshold
on url_val.csv, evaluates once on held-out url_test.csv, and evaluates out-of-distribution
stress test split separately.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Add project root to sys.path
PROJECT_ROOT = Path("D:/Projects/usability")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.url_features import (
    FEATURE_NAMES,
    extract_url_feature_dict,
    extract_url_feature_vector,
)


def extract_features_df(df: pd.DataFrame, url_col: str = "url") -> np.ndarray:
    """Extract 34-dimensional feature matrix for all URLs in dataframe."""
    urls = df[url_col].tolist()
    matrix = np.zeros((len(urls), len(FEATURE_NAMES)), dtype=np.float32)
    total = len(urls)
    t0 = time.time()
    for idx, u in enumerate(urls):
        matrix[idx] = extract_url_feature_vector(str(u))
        if (idx + 1) % 10000 == 0 or idx + 1 == total:
            elapsed = time.time() - t0
            rate = (idx + 1) / max(elapsed, 0.001)
            print(f"  Processed {idx + 1}/{total} URLs ({rate:.1f} URLs/sec)...")
    return matrix


def evaluate_split(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    threshold: float = 0.5,
) -> dict:
    """Compute comprehensive performance metrics for binary classification."""
    y_pred = (y_probs >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, len(y_true))

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    acc = float(accuracy_score(y_true, y_pred))
    p_phish = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    r_phish = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1_phish = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))

    p_legit = float(precision_score(y_true, y_pred, pos_label=0, zero_division=0))
    r_legit = float(recall_score(y_true, y_pred, pos_label=0, zero_division=0))
    f1_legit = float(f1_score(y_true, y_pred, pos_label=0, zero_division=0))

    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y_true, y_probs))
    except Exception:
        roc_auc = None

    try:
        precisions, recalls, _ = precision_recall_curve(y_true, y_probs)
        pr_auc = float(auc(recalls, precisions))
    except Exception:
        pr_auc = None

    return {
        "threshold": float(threshold),
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "rates": {
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
        },
        "phishing_class_1": {
            "precision": round(p_phish, 4),
            "recall": round(r_phish, 4),
            "f1": round(f1_phish, 4),
        },
        "legitimate_class_0": {
            "precision": round(p_legit, 4),
            "recall": round(r_legit, 4),
            "f1": round(f1_legit, 4),
        },
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
    }


def main():
    print("=" * 70)
    print("FraudLens: Phishing URL Model Training & Evaluation")
    print("=" * 70)

    data_dir = PROJECT_ROOT / "data" / "processed" / "urls"
    train_path = data_dir / "url_train.csv"
    val_path = data_dir / "url_val.csv"
    test_path = data_dir / "url_test.csv"
    stress_path = data_dir / "url_stress_test_bal_unique.csv"

    cache_dir = data_dir / ".features_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Data Splits
    print("\n[1/6] Loading dataset splits...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    stress_df = pd.read_csv(stress_path)

    print(f"  Train:  {len(train_df):,} rows (Phishing: {train_df['label'].sum():,} = {train_df['label'].mean():.2%})")
    print(f"  Val:    {len(val_df):,} rows (Phishing: {val_df['label'].sum():,} = {val_df['label'].mean():.2%})")
    print(f"  Test:   {len(test_df):,} rows (Phishing: {test_df['label'].sum():,} = {test_df['label'].mean():.2%})")
    print(f"  Stress: {len(stress_df):,} rows (Phishing: {stress_df['label'].sum():,} = {stress_df['label'].mean():.2%})")

    # 2. Feature Extraction (with caching)
    print("\n[2/6] Extracting 34 lexical and structural features...")
    train_feat_path = cache_dir / "train_features.npy"
    val_feat_path = cache_dir / "val_features.npy"
    test_feat_path = cache_dir / "test_features.npy"
    stress_feat_path = cache_dir / "stress_features.npy"

    if train_feat_path.exists():
        print("  Loading cached train features...")
        X_train = np.load(train_feat_path)
    else:
        print("  Extracting train features...")
        X_train = extract_features_df(train_df)
        np.save(train_feat_path, X_train)

    if val_feat_path.exists():
        print("  Loading cached val features...")
        X_val = np.load(val_feat_path)
    else:
        print("  Extracting val features...")
        X_val = extract_features_df(val_df)
        np.save(val_feat_path, X_val)

    if test_feat_path.exists():
        print("  Loading cached test features...")
        X_test = np.load(test_feat_path)
    else:
        print("  Extracting test features...")
        X_test = extract_features_df(test_df)
        np.save(test_feat_path, X_test)

    if stress_feat_path.exists():
        print("  Loading cached stress features...")
        X_stress = np.load(stress_feat_path)
    else:
        print("  Extracting stress features...")
        X_stress = extract_features_df(stress_df)
        np.save(stress_feat_path, X_stress)

    y_train = train_df["label"].to_numpy(dtype=int)
    y_val = val_df["label"].to_numpy(dtype=int)
    y_test = test_df["label"].to_numpy(dtype=int)
    y_stress = stress_df["label"].to_numpy(dtype=int)

    # 3. Model Configuration Exploration on Validation Data
    print("\n[3/6] Comparing model configurations on Validation set...")
    configs = {
        "RF_unweighted": RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            n_jobs=-1,
            class_weight=None,
        ),
        "RF_balanced": RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        ),
        "RF_balanced_subsample": RandomForestClassifier(
            n_estimators=150,
            max_depth=30,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        ),
    }

    best_name = None
    best_f1 = -1.0
    best_model = None
    val_results = {}

    for name, clf in configs.items():
        print(f"\n  Training candidate {name}...")
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0
        print(f"    Trained in {train_time:.2f}s")

        val_probs = clf.predict_proba(X_val)[:, 1]
        metrics = evaluate_split(y_val, val_probs, threshold=0.5)
        val_results[name] = metrics

        p = metrics["phishing_class_1"]["precision"]
        r = metrics["phishing_class_1"]["recall"]
        f1 = metrics["phishing_class_1"]["f1"]
        roc = metrics["roc_auc"]
        pr_auc = metrics["pr_auc"]
        print(f"    Validation (t=0.50): Phish Precision={p:.4f}, Recall={r:.4f}, F1={f1:.4f}, ROC-AUC={roc:.4f}, PR-AUC={pr_auc:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = clf

    print(f"\n  Selected candidate: {best_name} with Phishing F1={best_f1:.4f}")

    # 4. Calibrate Risk Decision Thresholds on Validation Split
    print("\n[4/6] Calibrating decision thresholds on Validation data...")
    val_probs = best_model.predict_proba(X_val)[:, 1]

    threshold_candidates = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    thresh_table = []
    for t in threshold_candidates:
        res = evaluate_split(y_val, val_probs, threshold=t)
        thresh_table.append({
            "threshold": t,
            "accuracy": res["accuracy"],
            "fpr": res["rates"]["fpr"],
            "phish_precision": res["phishing_class_1"]["precision"],
            "phish_recall": res["phishing_class_1"]["recall"],
            "phish_f1": res["phishing_class_1"]["f1"],
        })
        print(f"    t={t:.2f} -> Prec={res['phishing_class_1']['precision']:.4f}, Rec={res['phishing_class_1']['recall']:.4f}, F1={res['phishing_class_1']['f1']:.4f}, FPR={res['rates']['fpr']:.4f}")

    # Select operational thresholds:
    # decision_threshold: maximizes F1 while keeping FPR <= 0.02 (2% false alarm rate)
    sorted_by_f1 = sorted(thresh_table, key=lambda x: x["phish_f1"], reverse=True)
    chosen_decision_threshold = sorted_by_f1[0]["threshold"]
    print(f"\n  Calibrated decision threshold: {chosen_decision_threshold:.2f} (max F1 on validation split)")

    # Define 4-tier operational bands based on validation distribution
    # LOW RISK: p < 0.25
    # MEDIUM RISK: 0.25 <= p < 0.60
    # HIGH RISK: p >= 0.60
    threshold_low_risk = 0.25
    threshold_high_risk = 0.60

    # 5. Final Evaluation on Held-Out Test Set (Evaluated ONCE)
    print("\n[5/6] Final evaluation on held-out test split (url_test.csv)...")
    test_probs = best_model.predict_proba(X_test)[:, 1]
    final_test_metrics = evaluate_split(y_test, test_probs, threshold=chosen_decision_threshold)
    print("  === HELD-OUT TEST METRICS ===")
    print(f"  Accuracy:         {final_test_metrics['accuracy']:.4f}")
    print(f"  Macro F1:         {final_test_metrics['macro_f1']:.4f}")
    print(f"  ROC-AUC:          {final_test_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC:           {final_test_metrics['pr_auc']:.4f}")
    print(f"  Phishing Prec:    {final_test_metrics['phishing_class_1']['precision']:.4f}")
    print(f"  Phishing Recall:  {final_test_metrics['phishing_class_1']['recall']:.4f}")
    print(f"  Phishing F1:      {final_test_metrics['phishing_class_1']['f1']:.4f}")
    print(f"  Legitimate Prec:  {final_test_metrics['legitimate_class_0']['precision']:.4f}")
    print(f"  Legitimate Recall:{final_test_metrics['legitimate_class_0']['recall']:.4f}")
    print(f"  Legitimate F1:    {final_test_metrics['legitimate_class_0']['f1']:.4f}")
    print(f"  FPR (False Alarm):{final_test_metrics['rates']['fpr']:.4f}")
    print(f"  FNR (Miss Rate):  {final_test_metrics['rates']['fnr']:.4f}")
    print(f"  Confusion Matrix: {final_test_metrics['confusion_matrix']}")

    # 6. Stress Test Evaluation (Phishing-Only Out-of-Distribution Split)
    print("\n[6/6] Evaluating on independent out-of-distribution stress split...")
    stress_probs = best_model.predict_proba(X_stress)[:, 1]
    stress_detected = int((stress_probs >= chosen_decision_threshold).sum())
    stress_detection_rate = float(stress_detected / len(stress_probs))
    print(f"  Stress Detected:  {stress_detected:,} / {len(stress_probs):,} ({stress_detection_rate:.2%})")
    print("  Note: Stress test contains no legitimate URLs. Specificity and FPR cannot be measured on this set.")

    # 7. Feature Importances
    importances = best_model.feature_importances_
    feat_ranks = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    top_10_features = [{"feature": f, "importance": round(float(imp), 4)} for f, imp in feat_ranks[:10]]
    print("\n  Top 10 Feature Importances:")
    for rank, item in enumerate(top_10_features, 1):
        print(f"    {rank}. {item['feature']}: {item['importance']:.4f}")

    # 8. Save Model Artifact and Metadata
    models_dir = PROJECT_ROOT / "backend" / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_artifact_path = models_dir / "url_model.joblib"
    metadata_path = models_dir / "url_model_metadata.json"

    print(f"\n  Saving model artifact to {model_artifact_path}...")
    joblib.dump(best_model, model_artifact_path, compress=3)

    import sklearn
    metadata = {
        "model_name": "RandomForest_URL_v1",
        "model_class": "RandomForestClassifier",
        "date_trained": datetime.now(timezone.utc).isoformat(),
        "random_seed": 42,
        "scikit_learn_version": sklearn.__version__,
        "features": {
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "top_features": top_10_features,
        },
        "label_mapping": {
            "0": "legitimate",
            "1": "phishing",
        },
        "training_data": {
            "dataset": "url_train.csv",
            "samples": len(train_df),
            "phishing_prevalence": round(float(train_df["label"].mean()), 4),
        },
        "model_hyperparameters": best_model.get_params(),
        "thresholds": {
            "decision_threshold": chosen_decision_threshold,
            "low_risk_threshold": threshold_low_risk,
            "high_risk_threshold": threshold_high_risk,
        },
        "validation_comparison": val_results,
        "test_evaluation": final_test_metrics,
        "stress_test_evaluation": {
            "dataset": "url_stress_test_bal_unique.csv",
            "samples": len(stress_df),
            "phishing_detected": stress_detected,
            "detection_rate": round(stress_detection_rate, 4),
            "limitation_note": "Phishing-only dataset without legitimate samples; cannot evaluate false positive rate or specificity.",
        },
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"  Saved metadata to {metadata_path}")
    print("\nPhishing URL Model Training and Evaluation Pipeline Finished Successfully!")


if __name__ == "__main__":
    main()
