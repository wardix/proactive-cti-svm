from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


SELECTED_FEATURES_TABLE_4_16 = [
    {
        "feature": "IP Reputation Score (ip_reputation_score)",
        "justification": "Reflects the historical trustworthiness of an IP address based on threat intelligence sources. Helps identify known malicious entities such as botnets or blacklisted IPs.",
    },
    {
        "feature": "Attack Frequency (attack_frequency)",
        "justification": "Captures how often an IP or entity performs suspicious activities. High frequency indicates potential automated attacks such as DDoS or brute-force attempts.",
    },
    {
        "feature": "Protocol Type (protocol_tcp, protocol_udp, protocol_icmp)",
        "justification": "Represents the communication protocol (e.g., TCP, UDP, ICMP), which is associated with specific attack patterns and behaviors via One-Hot Encoding.",
    },
    {
        "feature": "Port Number (port)",
        "justification": "Indicates the targeted network service (e.g., SSH port 22, HTTP port 80, DNS port 53). Certain ports are more frequently targeted depending on attack objective.",
    },
    {
        "feature": "Payload Characteristics (payload_size)",
        "justification": "Describes properties of network data such as payload size in bytes, which reveals anomalies or malicious patterns.",
    },
    {
        "feature": "File Hashes - Derived Features (file_hash_score)",
        "justification": "File hashes uniquely identify files or malware samples. Transformed into numerical reputation/detection scores for effective use in SVM models.",
    },
]

ATTACK_TYPE_ENCODING_MAP = {
    "Normal": 0,
    "DDoS": 1,
    "SSH Brute Force": 2,
    "DNS Flood": 3,
    "SQL Injection": 4,
    "Malware Payload": 5,
    "Port Scanning": 6,
}


def encode_attack_type(atk: Any) -> int:
    s = str(atk or "Normal").strip()
    return ATTACK_TYPE_ENCODING_MAP.get(s, 1)


def extract_and_encode_features(
    clean_records: List[Dict[str, Any]],
    correlation_threshold: float = 0.92,
) -> Tuple[np.ndarray, np.ndarray, List[str], StandardScaler, Dict[str, Any]]:
    """
    Implements Section 4.4.5 (Feature Selection) and Section 4.5 (Data Preprocessing):
      - Step 1: Remove irrelevant features (IP string, raw timestamp, description)
      - Step 2: Encode categorical features:
          a) Attack Type -> Label Encoding
          b) Protocol -> One-Hot Encoding (TCP, UDP, ICMP)
      - Step 3: Convert Label to Numerical (Threat = 1, No Threat / Benign = -1)
      - Step 4: Final Numerical Feature Vector X
      - Step 5: Feature Scaling using Z-score standardization x' = (x - mu) / sigma
      - Correlation analysis to check and filter redundant features
    """
    rows = []
    labels = []

    for r in clean_records:
        proto = str(r.get("protocol", "TCP")).upper()
        atk_encoded = encode_attack_type(r.get("attack_type", "Normal"))
        port = float(r.get("port", 80))
        payload = float(r.get("payload_size", 0.0))
        ip_rep = float(r.get("ip_reputation_score", 50.0))
        freq = float(r.get("attack_frequency", 1.0))
        hash_score = float(r.get("file_hash_score", 0.0))
        lbl = 1 if int(r.get("label", 1)) == 1 else -1

        rows.append(
            {
                "attack_type_encoded": atk_encoded,
                "protocol_tcp": 1.0 if proto == "TCP" else 0.0,
                "protocol_udp": 1.0 if proto == "UDP" else 0.0,
                "protocol_icmp": 1.0 if proto == "ICMP" else 0.0,
                "port": port,
                "payload_size": payload,
                "ip_reputation_score": ip_rep,
                "attack_frequency": freq,
                "file_hash_score": hash_score,
            }
        )
        labels.append(lbl)

    df = pd.DataFrame(rows)
    y = np.array(labels, dtype=int)

    # Correlation analysis (Section 4.4.5)
    corr_matrix = df.corr().fillna(0.0)
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    dropped_redundant = [
        col for col in upper.columns if any(upper[col].abs() > correlation_threshold)
    ]

    kept_columns = [c for c in df.columns if c not in dropped_redundant]
    df_selected = df[kept_columns]

    # Step 5: Feature Scaling (Z-score standardization x' = (x - mu) / sigma)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_selected.values)

    # Prepare sample encoding & scaling preview for UI (matching Section 4.5 pages 93-94)
    sample_vectors = []
    for idx in range(min(8, len(df_selected))):
        raw_row = df_selected.iloc[idx].to_dict()
        scaled_row = {col: round(float(X_scaled[idx, j]), 4) for j, col in enumerate(kept_columns)}
        sample_vectors.append(
            {
                "source_ip": clean_records[idx].get("source_ip"),
                "raw_attack_type": clean_records[idx].get("attack_type"),
                "raw_protocol": clean_records[idx].get("protocol"),
                "unscaled_vector": {k: round(float(v), 2) for k, v in raw_row.items()},
                "scaled_vector": scaled_row,
                "label": int(y[idx]),
            }
        )

    feature_means = {col: round(float(scaler.mean_[i]), 4) for i, col in enumerate(kept_columns)}
    feature_stds = {col: round(float(scaler.scale_[i]), 4) for i, col in enumerate(kept_columns)}

    selection_info = {
        "selected_features_table_4_16": SELECTED_FEATURES_TABLE_4_16,
        "feature_columns": kept_columns,
        "dropped_redundant_features": dropped_redundant,
        "correlation_threshold": correlation_threshold,
        "correlation_matrix": {
            col: {r_col: round(float(corr_matrix.loc[col, r_col]), 3) for r_col in corr_matrix.columns}
            for col in corr_matrix.columns
        },
        "scaling_parameters": {
            "formula": "x' = (x - μ) / σ",
            "means_mu": feature_means,
            "stds_sigma": feature_stds,
        },
        "encoding_maps": {
            "attack_type_label_encoding": ATTACK_TYPE_ENCODING_MAP,
            "protocol_one_hot_encoding": ["TCP -> [1, 0, 0]", "UDP -> [0, 1, 0]", "ICMP -> [0, 0, 1]"],
            "target_label_encoding": {"Threat": 1, "No Threat / Benign": -1},
        },
        "sample_numerical_vectors": sample_vectors,
    }

    return X_scaled, y, kept_columns, scaler, selection_info


def transform_single_or_batch_for_prediction(
    records: List[Dict[str, Any]],
    feature_columns: List[str],
    scaler: StandardScaler,
) -> np.ndarray:
    """Transforms unseen Honeypot records using the saved feature columns and StandardScaler."""
    rows = []
    for r in records:
        proto = standardize_protocol_simple(r.get("protocol", "TCP"))
        atk_encoded = encode_attack_type(r.get("attack_type", "Normal"))
        port = float(r.get("port", 80))
        payload = float(r.get("payload_size", 0.0))
        ip_rep = float(r.get("ip_reputation_score", 50.0))
        freq = float(r.get("attack_frequency", 1.0))
        hash_score = float(r.get("file_hash_score", 0.0))

        full_row = {
            "attack_type_encoded": atk_encoded,
            "protocol_tcp": 1.0 if proto == "TCP" else 0.0,
            "protocol_udp": 1.0 if proto == "UDP" else 0.0,
            "protocol_icmp": 1.0 if proto == "ICMP" else 0.0,
            "port": port,
            "payload_size": payload,
            "ip_reputation_score": ip_rep,
            "attack_frequency": freq,
            "file_hash_score": hash_score,
        }
        rows.append([full_row[col] for col in feature_columns])

    X = np.array(rows, dtype=float)
    return scaler.transform(X)


def standardize_protocol_simple(val: Any) -> str:
    s = str(val or "TCP").strip().upper()
    if s == "6":
        return "TCP"
    if s == "17":
        return "UDP"
    if s == "1":
        return "ICMP"
    return s if s in ("TCP", "UDP", "ICMP") else "TCP"
