import os
from datetime import datetime
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
from sklearn import svm
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

from .feature_selection import (
    extract_and_encode_features,
    transform_single_or_batch_for_prediction,
)
from .preprocessing import run_preprocessing_pipeline


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_BUNDLE_PATH = os.path.join(MODEL_DIR, "svm_bundle.joblib")


def get_chapter_3_mathematical_illustration() -> Dict[str, Any]:
    """
    Returns the exact mathematical SVM derivation & 4-instance illustration
    from Chapter 3.2.4 (pages 62-65) and Chapter 4.7 (pages 95-96) of thesis.pdf.
    """
    return {
        "decision_function": "f(x) = sign(w^T x + b)",
        "objective_function_primal": "min_{w,b,ξ} (1/2)||w||^2 + C Σ ξ_i  subject to y_i(w^T x_i + b) >= 1 - ξ_i, ξ_i >= 0",
        "lagrangian_dual": "max_α W(α) = Σ α_i - (1/2) Σ_i Σ_j α_i α_j y_i y_j K(x_i, x_j)  subject to 0 <= α_i <= C, Σ α_i y_i = 0",
        "rbf_kernel_formula": "K(x_i, x_j) = exp(-γ ||x_i - x_j||^2)",
        "decision_rule": "If f(x) >= 0 -> Classify as Cyber Threat (+1); If f(x) < 0 -> Classify as Benign (-1)",
        "worked_example_page_62_65": {
            "raw_instances": [
                {"instance": 1, "source_ip": "10.10.1.2", "dest_port": 22, "encoded_x1": 1, "encoded_x2": 2, "y": -1},
                {"instance": 2, "source_ip": "10.10.1.5", "dest_port": 53, "encoded_x1": 2, "encoded_x2": 3, "y": -1},
                {"instance": 3, "source_ip": "10.10.1.7", "dest_port": 21, "encoded_x1": 3, "encoded_x2": 1, "y": 1},
                {"instance": 4, "source_ip": "10.10.1.9", "dest_port": 80, "encoded_x1": 4, "encoded_x2": 4, "y": 1},
            ],
            "lagrange_multipliers_alpha": [0.5, 0.0, 0.5, 0.0],
            "weight_vector_w": [2.0, 0.5],
            "bias_b": -5.0,
            "final_equation": "f(X) = sign([2, 0.5] · X - 5)",
        },
    }


def train_and_evaluate_svm(
    raw_records: List[Dict[str, Any]],
    kernel: str = "rbf",
    c_param: float = 1.0,
    gamma_param: str = "scale",
    train_ratio: float = 0.80,
    correlation_threshold: float = 0.92,
) -> Dict[str, Any]:
    """
    Runs the full pipeline on raw_records:
      1. Data Cleaning & Validation (Chapter 4.4)
      2. Feature Selection, Encoding & Z-Score Scaling (Chapter 4.4.5 & 4.5)
      3. Stratified Data Splitting 80% Train / 20% Test (Chapter 4.6)
      4. SVM Model Training (Chapter 4.7)
      5. Model Evaluation: Accuracy, Precision, Recall, F1, Confusion Matrix, ROC Curve (Chapter 4.10)
    """
    os.makedirs(MODEL_DIR, exist_ok=True)

    clean_records, preproc_report = run_preprocessing_pipeline(raw_records)
    if len(clean_records) < 10:
        raise ValueError("Dataset memiliki kurang dari 10 baris valid setelah proses cleaning.")

    X_scaled, y, feature_columns, scaler, selection_info = extract_and_encode_features(
        clean_records, correlation_threshold=correlation_threshold
    )

    test_size = round(1.0 - float(train_ratio), 2)
    if test_size <= 0.05 or test_size >= 0.5:
        test_size = 0.20

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled,
        y,
        test_size=test_size,
        random_state=42,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    kernel_clean = kernel.lower().strip()
    if kernel_clean not in ("rbf", "linear"):
        kernel_clean = "rbf"

    # Parse gamma if numeric string
    gamma_val: Any = gamma_param
    if isinstance(gamma_param, str) and gamma_param not in ("scale", "auto"):
        try:
            gamma_val = float(gamma_param)
        except ValueError:
            gamma_val = "scale"

    clf = svm.SVC(
        kernel=kernel_clean,
        C=float(c_param),
        gamma=gamma_val if kernel_clean == "rbf" else "scale",
        probability=True,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    decision_scores = clf.decision_function(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))

    # Confusion Matrix: labels [-1 (Benign), 1 (Threat)]
    cm = confusion_matrix(y_test, y_pred, labels=[1, -1])
    tp = int(cm[0, 0])
    fn = int(cm[0, 1])
    fp = int(cm[1, 0])
    tn = int(cm[1, 1])

    # ROC Curve & AUC
    y_test_binary = (y_test == 1).astype(int)
    auc_val = float(roc_auc_score(y_test_binary, decision_scores))
    fpr_arr, tpr_arr, thresh_arr = roc_curve(y_test_binary, decision_scores)

    # Downsample ROC points for clean JSON charting (~40 points)
    indices = np.linspace(0, len(fpr_arr) - 1, min(45, len(fpr_arr)), dtype=int)
    roc_points = [
        {
            "fpr": round(float(fpr_arr[i]), 4),
            "tpr": round(float(tpr_arr[i]), 4),
        }
        for i in np.unique(indices)
    ]

    support_vectors_total = int(np.sum(clf.n_support_))
    linear_weights = None
    linear_bias = float(clf.intercept_[0])
    if kernel_clean == "linear":
        linear_weights = {
            col: round(float(clf.coef_[0][idx]), 4)
            for idx, col in enumerate(feature_columns)
        }

    bundle = {
        "model": clf,
        "scaler": scaler,
        "feature_columns": feature_columns,
        "kernel": kernel_clean,
        "c_param": float(c_param),
        "gamma_param": str(gamma_param),
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "auc": round(auc_val, 4),
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
        },
    }
    joblib.dump(bundle, MODEL_BUNDLE_PATH)

    threat_count = int(np.sum(y == 1))
    benign_count = int(np.sum(y == -1))

    return {
        "trained_at": bundle["trained_at"],
        "hyperparameters": {
            "kernel": kernel_clean,
            "c_param": float(c_param),
            "gamma_param": str(gamma_param),
            "train_ratio": round(1.0 - test_size, 2),
            "test_ratio": test_size,
        },
        "dataset_split": {
            "total_clean_samples": int(len(y)),
            "train_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
            "threat_count": threat_count,
            "benign_count": benign_count,
        },
        "svm_internals": {
            "support_vectors_count": support_vectors_total,
            "support_vectors_per_class": {
                "benign_minus_1": int(clf.n_support_[0]),
                "threat_plus_1": int(clf.n_support_[1]),
            },
            "intercept_bias_b": round(linear_bias, 4),
            "linear_weights_w": linear_weights,
        },
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "auc": round(auc_val, 4),
        },
        "confusion_matrix": {
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "table_5_3_reference": {"tp": 1120, "fn": 130, "fp": 105, "tn": 1145},
        },
        "roc_curve": roc_points,
        "preprocessing_report": preproc_report,
        "feature_selection_report": selection_info,
        "mathematical_formulation": get_chapter_3_mathematical_illustration(),
    }


def predict_unseen_data(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Applies the trained SVM model to unseen Honeypot / CTI records (Section 3.2.6 & 4.8).
    Returns predicted class (1 = Cyber Threat, -1 = Benign), decision function value f(x),
    and probability confidence.
    """
    if not os.path.exists(MODEL_BUNDLE_PATH):
        raise FileNotFoundError(
            "Model SVM belum dilatih. Silakan jalankan Training SVM terlebih dahulu."
        )

    bundle = joblib.load(MODEL_BUNDLE_PATH)
    clf = bundle["model"]
    scaler = bundle["scaler"]
    feature_columns = bundle["feature_columns"]

    X_scaled = transform_single_or_batch_for_prediction(records, feature_columns, scaler)
    preds = clf.predict(X_scaled)
    decision_vals = clf.decision_function(X_scaled)
    probs = clf.predict_proba(X_scaled)

    results = []
    for idx, rec in enumerate(records):
        pred_label = int(preds[idx])
        dec_val = float(decision_vals[idx])
        # Classes in SVC are [-1, 1]
        threat_prob = float(probs[idx][1]) if len(probs[idx]) > 1 else (0.95 if pred_label == 1 else 0.05)
        conf_pct = round((threat_prob if pred_label == 1 else (1.0 - threat_prob)) * 100.0, 2)

        out = dict(rec)
        out["predicted_label"] = pred_label
        out["prediction_text"] = "Cyber Threat (1)" if pred_label == 1 else "Benign / Non-Threat (-1)"
        out["decision_value"] = round(dec_val, 4)
        out["confidence_score"] = conf_pct
        out["scaled_features"] = {
            col: round(float(X_scaled[idx, j]), 4) for j, col in enumerate(feature_columns)
        }
        results.append(out)

    return results


def get_saved_model_status() -> Optional[Dict[str, Any]]:
    if not os.path.exists(MODEL_BUNDLE_PATH):
        return None
    bundle = joblib.load(MODEL_BUNDLE_PATH)
    return {
        "is_trained": True,
        "kernel": bundle.get("kernel"),
        "c_param": bundle.get("c_param"),
        "gamma_param": bundle.get("gamma_param"),
        "trained_at": bundle.get("trained_at"),
        "feature_columns": bundle.get("feature_columns"),
        "metrics": bundle.get("metrics"),
    }
