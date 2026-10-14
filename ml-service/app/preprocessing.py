import re
from datetime import datetime
from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd


IPV4_REGEX = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)

IANA_PROTOCOL_MAP = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
}


def standardize_timestamp(val: Any) -> str:
    """Converts heterogeneous timestamp formats to ISO YYYY-MM-DD HH:MM:SS (Table 4.8-4.11)."""
    if val is None:
        return ""
    s = str(val).strip()
    if not s or s.upper() in ("NULL", "NONE", "NAN"):
        return ""
    # Replace T separator
    s_clean = s.replace("T", " ").replace("Z", "")
    if "." in s_clean:
        s_clean = s_clean.split(".")[0]

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %I:%M %p",
        "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(s_clean, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return s_clean


def standardize_protocol(val: Any) -> str:
    """Converts protocol strings or IANA numeric codes to uppercase TCP/UDP/ICMP (Table 4.8-4.11)."""
    if val is None:
        return ""
    s = str(val).strip()
    if not s or s.upper() in ("NULL", "NONE", "NAN", "MISSING"):
        return ""
    if s in IANA_PROTOCOL_MAP:
        return IANA_PROTOCOL_MAP[s]
    upper_s = s.upper()
    if upper_s in ("TCP", "UDP", "ICMP"):
        return upper_s
    return upper_s


def parse_payload_size(val: Any) -> float:
    """Strips text units like 'bytes' and converts to float (Table 4.8-4.11)."""
    if val is None:
        return np.nan
    s = str(val).strip().lower()
    if not s or s in ("null", "none", "nan", "missing"):
        return np.nan
    s = s.replace("bytes", "").replace("byte", "").replace('"', "").replace("“", "").replace("”", "").strip()
    try:
        return float(s)
    except ValueError:
        return np.nan


def standardize_label(val: Any) -> int:
    """Standardizes label to 1 (Cyber Threat) or -1 (Benign/Normal) (Section 3.2.1 & Table 4.9)."""
    if val is None:
        return -1
    s = str(val).strip().lower()
    if s in ("1", "+1", "threat", "cyber threat", "malicious", "yes", "true", "high"):
        return 1
    return -1


def run_preprocessing_pipeline(raw_records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Executes the complete Data Cleaning and Data Validation pipeline from
    Chapter 4.4.3 and 4.4.4 of thesis.pdf:
      1. Removal of Corrupted Entries (Table 4.14 & 4.15)
      2. Standardizing Formats & Schema Consistency (Table 4.8 - 4.11)
      3. Removal of Duplicate Records: D_clean = D - D_duplicate (Table 4.2 & 4.3)
      4. Handling Missing Values: Mean & Mode Imputation (Table 4.4 & 4.5)
      5. Verifying Feature Ranges: Port (0-65535) & Payload Size (>= 0) (Table 4.12 & 4.13)
      6. Filtering Irrelevant Attributes: event_id, description (Table 4.6 & 4.7)
    """
    initial_count = len(raw_records)

    # -------------------------------------------------------------------------
    # Stage A: Corrupted Entries Check (Table 4.14 & 4.15)
    # -------------------------------------------------------------------------
    corrupted_removed = []
    after_corrupted = []
    for rec in raw_records:
        raw_ts = rec.get("timestamp")
        raw_ip = str(rec.get("source_ip") or "").strip()
        raw_port = str(rec.get("port") if rec.get("port") is not None else "").strip()

        ts_std = standardize_timestamp(raw_ts)
        ip_valid = bool(IPV4_REGEX.match(raw_ip))
        port_is_nan = raw_port.upper() in ("NAN", "NULL", "NONE", "") or not re.match(r"^-?\d+$", raw_port)

        if not ts_std or not ip_valid or port_is_nan:
            corrupted_removed.append(
                {
                    "timestamp": str(raw_ts),
                    "source_ip": raw_ip,
                    "protocol": str(rec.get("protocol")),
                    "port": raw_port,
                    "payload_size": str(rec.get("payload_size")),
                    "reason": (
                        "Missing timestamp (NULL)"
                        if not ts_std
                        else ("Invalid IP address (???)" if not ip_valid else "Non-numeric port value (NaN)")
                    ),
                }
            )
            continue

        rec_copy = dict(rec)
        rec_copy["raw_timestamp"] = str(raw_ts)
        rec_copy["timestamp"] = ts_std
        rec_copy["port"] = int(raw_port)
        after_corrupted.append(rec_copy)

    # -------------------------------------------------------------------------
    # Stage B: Standardizing Formats & Schema Consistency (Table 4.8 - 4.11)
    # -------------------------------------------------------------------------
    standardized_examples = []
    after_standardized = []
    for rec in after_corrupted:
        raw_proto = rec.get("protocol")
        raw_payload = rec.get("payload_size")
        raw_lbl = rec.get("label")

        std_proto = standardize_protocol(raw_proto)
        num_payload = parse_payload_size(raw_payload)
        std_lbl = standardize_label(raw_lbl)

        if (
            str(raw_proto) != std_proto
            or ("bytes" in str(raw_payload).lower())
            or ("/" in str(rec.get("raw_timestamp", "")))
        ):
            if len(standardized_examples) < 10:
                standardized_examples.append(
                    {
                        "source_ip": rec.get("source_ip"),
                        "before_timestamp": rec.get("raw_timestamp"),
                        "after_timestamp": rec.get("timestamp"),
                        "before_protocol": str(raw_proto),
                        "after_protocol": std_proto or "MISSING",
                        "before_payload": str(raw_payload),
                        "after_payload": num_payload if not np.isnan(num_payload) else "MISSING",
                        "before_label": str(raw_lbl),
                        "after_label": "Threat (1)" if std_lbl == 1 else "Normal (-1)",
                    }
                )

        rec_copy = dict(rec)
        rec_copy["protocol"] = std_proto if std_proto else None
        rec_copy["payload_size"] = None if np.isnan(num_payload) else float(num_payload)
        rec_copy["label"] = std_lbl
        after_standardized.append(rec_copy)

    # -------------------------------------------------------------------------
    # Stage C: Duplicate Removal D_clean = D - D_duplicate (Table 4.2 & 4.3)
    # -------------------------------------------------------------------------
    seen_keys = set()
    duplicates_removed = []
    after_dedup = []
    for rec in after_standardized:
        key = (
            rec.get("timestamp"),
            rec.get("source_ip"),
            rec.get("protocol"),
            rec.get("port"),
            rec.get("payload_size"),
            rec.get("attack_type"),
        )
        if key in seen_keys:
            duplicates_removed.append(
                {
                    "timestamp": rec.get("timestamp"),
                    "source_ip": rec.get("source_ip"),
                    "protocol": rec.get("protocol"),
                    "port": rec.get("port"),
                    "payload_size": rec.get("payload_size"),
                    "attack_type": rec.get("attack_type"),
                }
            )
            continue
        seen_keys.add(key)
        after_dedup.append(rec)

    # -------------------------------------------------------------------------
    # Stage D: Missing Value Imputation - Mean & Mode (Table 4.4 & 4.5)
    # -------------------------------------------------------------------------
    valid_payloads = [
        r["payload_size"]
        for r in after_dedup
        if r.get("payload_size") is not None and r.get("payload_size") >= 0
    ]
    mean_payload = round(float(np.mean(valid_payloads)), 2) if valid_payloads else 1166.67

    valid_protocols = [r["protocol"] for r in after_dedup if r.get("protocol")]
    mode_protocol = pd.Series(valid_protocols).mode().iloc[0] if valid_protocols else "TCP"

    valid_attacks = [r["attack_type"] for r in after_dedup if r.get("attack_type")]
    mode_attack = pd.Series(valid_attacks).mode().iloc[0] if valid_attacks else "DDoS"

    imputed_examples = []
    after_imputation = []
    for rec in after_dedup:
        rec_copy = dict(rec)
        missing_fields = []
        if rec_copy.get("payload_size") is None:
            missing_fields.append(f"payload_size -> Mean ({mean_payload})")
            rec_copy["payload_size"] = mean_payload
        if not rec_copy.get("protocol"):
            missing_fields.append(f"protocol -> Mode ({mode_protocol})")
            rec_copy["protocol"] = mode_protocol
        if not rec_copy.get("attack_type"):
            missing_fields.append(f"attack_type -> Mode ({mode_attack})")
            rec_copy["attack_type"] = mode_attack

        if missing_fields and len(imputed_examples) < 10:
            imputed_examples.append(
                {
                    "source_ip": rec_copy.get("source_ip"),
                    "imputed_fields": ", ".join(missing_fields),
                    "payload_size": rec_copy.get("payload_size"),
                    "protocol": rec_copy.get("protocol"),
                    "attack_type": rec_copy.get("attack_type"),
                }
            )
        after_imputation.append(rec_copy)

    # -------------------------------------------------------------------------
    # Stage E: Verifying Feature Ranges (Port 0-65535, Payload >= 0) (Table 4.12 & 4.13)
    # -------------------------------------------------------------------------
    range_issues = []
    after_range = []
    for rec in after_imputation:
        rec_copy = dict(rec)
        port_val = int(rec_copy.get("port", 0))
        payload_val = float(rec_copy.get("payload_size", 0.0))

        if port_val < 0 or port_val > 65535:
            range_issues.append(
                {
                    "timestamp": rec_copy.get("timestamp"),
                    "source_ip": rec_copy.get("source_ip"),
                    "protocol": rec_copy.get("protocol"),
                    "port": port_val,
                    "payload_size": payload_val,
                    "action": f"Removed (Invalid port {port_val}, valid range: 0-65535)",
                }
            )
            continue

        if payload_val < 0:
            range_issues.append(
                {
                    "timestamp": rec_copy.get("timestamp"),
                    "source_ip": rec_copy.get("source_ip"),
                    "protocol": rec_copy.get("protocol"),
                    "port": port_val,
                    "payload_size": payload_val,
                    "action": f"Corrected payload_size from {payload_val} to 0",
                }
            )
            rec_copy["payload_size"] = 0.0

        rec_copy["is_cleaned"] = True
        after_range.append(rec_copy)

    # -------------------------------------------------------------------------
    # Stage F: Filtering Irrelevant Attributes Summary (Table 4.6 & 4.7)
    # -------------------------------------------------------------------------
    irrelevant_attributes_filtered = [
        {"attribute": "event_id", "reason": "Only an identifier, no predictive value"},
        {"attribute": "timestamp", "reason": "Retained for audit log; excluded from SVM numerical vector"},
        {"attribute": "description", "reason": "Unstructured text, removed before numerical encoding"},
        {"attribute": "source_ip", "reason": "Transformed into IP Reputation Score & Attack Frequency"},
    ]

    report = {
        "counts": {
            "initial_raw_records": initial_count,
            "after_corrupted_removal": len(after_corrupted),
            "corrupted_removed_count": len(corrupted_removed),
            "after_duplicate_removal": len(after_dedup),
            "duplicates_removed_count": len(duplicates_removed),
            "imputed_records_count": len(imputed_examples),
            "range_anomalies_count": len(range_issues),
            "final_clean_records": len(after_range),
        },
        "imputation_stats": {
            "numerical_mean_payload_size": mean_payload,
            "categorical_mode_protocol": mode_protocol,
            "categorical_mode_attack_type": mode_attack,
            "thesis_example_mean": 1166.67,  # (1500 + 800 + 1200) / 3 from page 83
        },
        "stage_examples": {
            "duplicates_removed": duplicates_removed[:10],
            "imputed_records": imputed_examples[:10],
            "standardized_records": standardized_examples[:10],
            "range_validation_issues": range_issues[:10],
            "corrupted_removed": corrupted_removed[:10],
            "irrelevant_attributes_filtered": irrelevant_attributes_filtered,
        },
    }

    return after_range, report
