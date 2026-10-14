-- ============================================================================
-- Proactive Cyber Security Defense Model Through Cyber Threat Intelligence (CTI)
-- Database Schema (MySQL) - Based on Chapter 4 (Table 4.1 & Table 4.16)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cti_svm_defense
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cti_svm_defense;

-- ----------------------------------------------------------------------------
-- 1. Table: threats (Raw & Preprocessed CTI Dataset from MISP, Wazuh, Honeypot)
--    Ref: Table 4.1 (page 80) & Table 4.16 (page 92) of thesis.pdf
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(64) NULL COMMENT 'Original event ID from MISP/Wazuh/Honeypot',
    timestamp TIMESTAMP NULL COMMENT 'Time stamp event',
    raw_timestamp VARCHAR(64) NULL COMMENT 'Raw timestamp before standardization',
    source_ip VARCHAR(45) NOT NULL COMMENT 'Source IP address',
    dest_ip VARCHAR(45) NULL DEFAULT '68.183.44.135' COMMENT 'Destination IP address',
    src_port INT NULL DEFAULT 0 COMMENT 'Source port',
    port INT NULL COMMENT 'Destination port (0-65535)',
    raw_port VARCHAR(32) NULL COMMENT 'Raw destination port before validation',
    protocol VARCHAR(16) NOT NULL DEFAULT 'TCP' COMMENT 'Network protocol (TCP, UDP, ICMP)',
    raw_protocol VARCHAR(32) NULL COMMENT 'Raw protocol before standardization',
    payload_size DOUBLE NOT NULL DEFAULT 0 COMMENT 'Payload size in bytes',
    raw_payload_size VARCHAR(64) NULL COMMENT 'Raw payload size before cleaning',
    attack_type VARCHAR(100) NULL COMMENT 'Attack category (SSH Brute Force, DDoS, SQLi, Malware, Normal, etc.)',
    domain_name VARCHAR(255) NULL COMMENT 'Associated domain name (IoC)',
    file_hash VARCHAR(128) NULL COMMENT 'Associated file hash MD5/SHA256 (IoC)',
    file_hash_score DOUBLE NOT NULL DEFAULT 0.0 COMMENT 'Derived numerical feature from file hash reputation',
    ip_reputation_score DOUBLE NOT NULL DEFAULT 0.0 COMMENT 'Historical IP trustworthiness/maliciousness score (0-100)',
    attack_frequency INT NOT NULL DEFAULT 1 COMMENT 'Frequency of suspicious actions from source IP',
    ids_type VARCHAR(50) NULL DEFAULT 'network' COMMENT 'IDS classification type',
    source_platform ENUM('MISP', 'Wazuh', 'Honeypot', 'Upload') NOT NULL DEFAULT 'Honeypot' COMMENT 'Origin CTI platform',
    description TEXT NULL COMMENT 'Unstructured event description (filtered before SVM)',
    label TINYINT NOT NULL DEFAULT 1 COMMENT 'Threat label: 1 = Cyber Threat (TP), -1 = Benign/Non-threat (TN)',
    raw_label VARCHAR(32) NULL COMMENT 'Raw label before standardization',
    is_cleaned BOOLEAN NOT NULL DEFAULT TRUE COMMENT 'Whether record passed data cleaning and validation',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_ip (source_ip),
    INDEX idx_label (label),
    INDEX idx_source_platform (source_platform),
    INDEX idx_timestamp (timestamp)
);

-- ----------------------------------------------------------------------------
-- 2. Table: svm_training_runs (Stores SVM Model Training & Evaluation Results)
--    Ref: Section 4.7 & Section 4.10 (page 95-101) of thesis.pdf
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS svm_training_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    kernel VARCHAR(32) NOT NULL DEFAULT 'rbf' COMMENT 'SVM Kernel: rbf or linear',
    c_param DOUBLE NOT NULL DEFAULT 1.0 COMMENT 'Regularization parameter C',
    gamma_param VARCHAR(32) NOT NULL DEFAULT 'scale' COMMENT 'Kernel coefficient gamma',
    train_ratio DOUBLE NOT NULL DEFAULT 0.80 COMMENT 'Training split ratio (default 80%)',
    total_samples INT NOT NULL DEFAULT 0,
    train_samples INT NOT NULL DEFAULT 0,
    test_samples INT NOT NULL DEFAULT 0,
    threat_count INT NOT NULL DEFAULT 0,
    benign_count INT NOT NULL DEFAULT 0,
    support_vectors_count INT NOT NULL DEFAULT 0,
    accuracy DOUBLE NOT NULL DEFAULT 0.0,
    precision_score DOUBLE NOT NULL DEFAULT 0.0,
    recall_score DOUBLE NOT NULL DEFAULT 0.0,
    f1_score DOUBLE NOT NULL DEFAULT 0.0,
    auc_score DOUBLE NOT NULL DEFAULT 0.0,
    tp INT NOT NULL DEFAULT 0,
    tn INT NOT NULL DEFAULT 0,
    fp INT NOT NULL DEFAULT 0,
    fn INT NOT NULL DEFAULT 0,
    selected_features_json JSON NULL,
    confusion_matrix_json JSON NULL,
    roc_curve_json JSON NULL,
    preprocessing_summary_json JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 3. Table: honeypot_predictions (Real-time / Batch Unseen Data Predictions)
--    Ref: Section 3.2.6, 3.3 & 4.8 of thesis.pdf
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS honeypot_predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NULL DEFAULT '68.183.44.135',
    src_port INT NULL DEFAULT 0,
    port INT NOT NULL,
    protocol VARCHAR(16) NOT NULL DEFAULT 'TCP',
    payload_size DOUBLE NOT NULL DEFAULT 0,
    attack_type VARCHAR(100) NULL,
    honeypot_sensor VARCHAR(64) NULL DEFAULT 'Cowrie',
    domain_name VARCHAR(255) NULL,
    file_hash VARCHAR(128) NULL,
    ip_reputation_score DOUBLE NOT NULL DEFAULT 50.0,
    attack_frequency INT NOT NULL DEFAULT 1,
    file_hash_score DOUBLE NOT NULL DEFAULT 0.0,
    predicted_label TINYINT NOT NULL COMMENT '1 = Cyber Threat, -1 = Benign',
    confidence_score DOUBLE NOT NULL DEFAULT 0.0,
    decision_value DOUBLE NOT NULL DEFAULT 0.0 COMMENT 'f(x) = w^T x + b value',
    raw_log_json JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pred_label (predicted_label),
    INDEX idx_pred_ip (source_ip)
);

-- ----------------------------------------------------------------------------
-- 4. Table: cti_source_configs (Connection settings for MISP, Wazuh, Honeypot)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_source_configs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_name VARCHAR(32) NOT NULL UNIQUE COMMENT 'MISP, Wazuh, Honeypot',
    base_url VARCHAR(255) NULL,
    api_key VARCHAR(512) NULL,
    username VARCHAR(128) NULL,
    password VARCHAR(255) NULL,
    verify_ssl BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at TIMESTAMP NULL,
    last_sync_count INT NOT NULL DEFAULT 0,
    last_status VARCHAR(64) NULL DEFAULT 'Ready (Simulation Fallback Available)',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
