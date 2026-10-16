"""Model candidate comparison and validation experiment script.

Trains candidate configurations on sms_train.csv and evaluates strictly on sms_val.csv.
The test set (sms_test.csv) is strictly NOT accessed during this phase.
"""

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline


def run_experiments():
    train_path = Path("D:/Projects/usability/data/processed/sms/sms_train.csv")
    val_path = Path("D:/Projects/usability/data/processed/sms/sms_val.csv")

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)

    X_train, y_train = df_train["text"], df_train["is_scam"]
    X_val, y_val = df_val["text"], df_val["is_scam"]

    configs = {
        "Config_1_Word11_Default": {
            "vectorizer": TfidfVectorizer(ngram_range=(1, 1), lowercase=True, max_features=5000),
            "classifier": LogisticRegression(random_state=42, C=1.0, class_weight=None, max_iter=1000),
        },
        "Config_2_Word12_Default": {
            "vectorizer": TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=10000, sublinear_tf=True),
            "classifier": LogisticRegression(random_state=42, C=1.0, class_weight=None, max_iter=1000),
        },
        "Config_3_Word12_Balanced": {
            "vectorizer": TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=10000, sublinear_tf=True),
            "classifier": LogisticRegression(random_state=42, C=1.0, class_weight="balanced", max_iter=1000),
        },
        "Config_4_Word12_C10": {
            "vectorizer": TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=10000, sublinear_tf=True),
            "classifier": LogisticRegression(random_state=42, C=10.0, class_weight=None, max_iter=1000),
        },
        "Config_5_WordChar_C10": {
            "vectorizer": TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=10000, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b|[^\w\s]"),
            "classifier": LogisticRegression(random_state=42, C=10.0, class_weight=None, max_iter=1000),
        },
    }

    results = []

    print("=== Model Candidate Experiments on Validation Set ===")
    for name, cfg in configs.items():
        pipe = Pipeline([
            ("tfidf", cfg["vectorizer"]),
            ("clf", cfg["classifier"]),
        ])
        pipe.fit(X_train, y_train)

        # Probabilities on validation set
        val_probs = pipe.predict_proba(X_val)[:, 1]
        val_preds_default = (val_probs >= 0.5).astype(int)

        prec_spam = precision_score(y_val, val_preds_default, pos_label=1, zero_division=0)
        rec_spam = recall_score(y_val, val_preds_default, pos_label=1, zero_division=0)
        f1_spam = f1_score(y_val, val_preds_default, pos_label=1, zero_division=0)
        macro_f1 = f1_score(y_val, val_preds_default, average="macro")

        # Threshold experiment for this config: find threshold maximizing F1 on validation set
        best_thresh = 0.5
        best_f1 = f1_spam
        for thresh in np.arange(0.2, 0.85, 0.05):
            preds_t = (val_probs >= thresh).astype(int)
            f1_t = f1_score(y_val, preds_t, pos_label=1, zero_division=0)
            if f1_t > best_f1:
                best_f1 = f1_t
                best_thresh = thresh

        preds_opt = (val_probs >= best_thresh).astype(int)
        prec_opt = precision_score(y_val, preds_opt, pos_label=1, zero_division=0)
        rec_opt = recall_score(y_val, preds_opt, pos_label=1, zero_division=0)
        macro_f1_opt = f1_score(y_val, preds_opt, average="macro")

        print(f"\n[{name}]")
        print(f"  Threshold 0.50 -> Spam Prec: {prec_spam:.4f}, Rec: {rec_spam:.4f}, F1: {f1_spam:.4f}, Macro F1: {macro_f1:.4f}")
        print(f"  Best Thresh ({best_thresh:.2f}) -> Spam Prec: {prec_opt:.4f}, Rec: {rec_opt:.4f}, F1: {best_f1:.4f}, Macro F1: {macro_f1_opt:.4f}")
        cm = confusion_matrix(y_val, val_preds_default)
        print(f"  Confusion Matrix (default 0.5): TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}")

        results.append({
            "config": name,
            "prec_spam": prec_spam,
            "rec_spam": rec_spam,
            "f1_spam": f1_spam,
            "macro_f1": macro_f1,
            "best_thresh": best_thresh,
            "best_f1": best_f1,
            "macro_f1_opt": macro_f1_opt,
        })

    return results


if __name__ == "__main__":
    run_experiments()
