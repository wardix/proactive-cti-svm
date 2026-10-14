<?php

namespace App\Support;

use PDO;

class Database
{
    private static ?PDO $pdo = null;

    public static function connection(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $driver = strtolower((string) Env::get('DB_CONNECTION', 'sqlite'));

        if ($driver === 'mysql') {
            $host = Env::get('DB_HOST', '127.0.0.1');
            $port = Env::get('DB_PORT', '3306');
            $dbName = Env::get('DB_DATABASE', 'cti_svm_defense');
            $user = Env::get('DB_USERNAME', 'root');
            $pass = Env::get('DB_PASSWORD', '');
            $dsn = "mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4";
            self::$pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
        } else {
            $relPath = (string) Env::get('DB_DATABASE', 'database/database.sqlite');
            $dbPath = str_starts_with($relPath, '/')
                ? $relPath
                : dirname(__DIR__, 2) . '/' . $relPath;
            $dir = dirname($dbPath);
            if (!is_dir($dir)) {
                mkdir($dir, 0775, true);
            }
            self::$pdo = new PDO("sqlite:{$dbPath}", null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            self::$pdo->exec('PRAGMA journal_mode = WAL;');
        }

        self::migrate(self::$pdo, $driver);
        return self::$pdo;
    }

    private static function migrate(PDO $pdo, string $driver): void
    {
        $autoInc = $driver === 'mysql' ? 'INT AUTO_INCREMENT PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT';

        $pdo->exec("
            CREATE TABLE IF NOT EXISTS threats (
                id {$autoInc},
                event_id VARCHAR(64) NULL,
                timestamp VARCHAR(64) NULL,
                source_ip VARCHAR(64) NOT NULL,
                dest_ip VARCHAR(64) NULL DEFAULT '68.183.44.135',
                src_port INT NULL DEFAULT 0,
                port VARCHAR(32) NULL,
                protocol VARCHAR(32) NULL DEFAULT 'TCP',
                payload_size VARCHAR(64) NULL DEFAULT '0',
                attack_type VARCHAR(100) NULL,
                domain_name VARCHAR(255) NULL,
                file_hash VARCHAR(128) NULL,
                file_hash_score DOUBLE NOT NULL DEFAULT 0.0,
                ip_reputation_score DOUBLE NOT NULL DEFAULT 0.0,
                attack_frequency INT NOT NULL DEFAULT 1,
                ids_type VARCHAR(50) NULL DEFAULT 'network',
                source_platform VARCHAR(32) NOT NULL DEFAULT 'Honeypot',
                description TEXT NULL,
                label VARCHAR(32) NOT NULL DEFAULT '1',
                is_cleaned INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $pdo->exec("
            CREATE TABLE IF NOT EXISTS svm_training_runs (
                id {$autoInc},
                kernel VARCHAR(32) NOT NULL DEFAULT 'rbf',
                c_param DOUBLE NOT NULL DEFAULT 1.0,
                gamma_param VARCHAR(32) NOT NULL DEFAULT 'scale',
                train_ratio DOUBLE NOT NULL DEFAULT 0.80,
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
                selected_features_json TEXT NULL,
                confusion_matrix_json TEXT NULL,
                roc_curve_json TEXT NULL,
                preprocessing_summary_json TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $pdo->exec("
            CREATE TABLE IF NOT EXISTS honeypot_predictions (
                id {$autoInc},
                timestamp VARCHAR(64) NOT NULL,
                source_ip VARCHAR(64) NOT NULL,
                dest_ip VARCHAR(64) NULL DEFAULT '68.183.44.135',
                src_port INT NULL DEFAULT 0,
                port INT NOT NULL,
                protocol VARCHAR(32) NOT NULL DEFAULT 'TCP',
                payload_size DOUBLE NOT NULL DEFAULT 0,
                attack_type VARCHAR(100) NULL,
                honeypot_sensor VARCHAR(64) NULL DEFAULT 'Cowrie',
                domain_name VARCHAR(255) NULL,
                file_hash VARCHAR(128) NULL,
                ip_reputation_score DOUBLE NOT NULL DEFAULT 50.0,
                attack_frequency INT NOT NULL DEFAULT 1,
                file_hash_score DOUBLE NOT NULL DEFAULT 0.0,
                predicted_label INT NOT NULL,
                confidence_score DOUBLE NOT NULL DEFAULT 0.0,
                decision_value DOUBLE NOT NULL DEFAULT 0.0,
                raw_log_json TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $pdo->exec("
            CREATE TABLE IF NOT EXISTS cti_source_configs (
                id {$autoInc},
                source_name VARCHAR(32) NOT NULL UNIQUE,
                base_url VARCHAR(255) NULL,
                api_key VARCHAR(512) NULL,
                username VARCHAR(128) NULL,
                password VARCHAR(255) NULL,
                verify_ssl INT NOT NULL DEFAULT 0,
                is_enabled INT NOT NULL DEFAULT 1,
                last_sync_at VARCHAR(64) NULL,
                last_sync_count INT NOT NULL DEFAULT 0,
                last_status VARCHAR(128) NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        // Seed default CTI sources (MISP, Wazuh, Honeypot - NO OpenCTI per user spec)
        $count = (int) $pdo->query("SELECT COUNT(*) FROM cti_source_configs")->fetchColumn();
        if ($count === 0) {
            $stmt = $pdo->prepare("
                INSERT INTO cti_source_configs (source_name, base_url, api_key, username, password, verify_ssl, is_enabled, last_status)
                VALUES (:source_name, :base_url, :api_key, :username, :password, :verify_ssl, 1, :last_status)
            ");

            $stmt->execute([
                ':source_name' => 'MISP',
                ':base_url' => (string) Env::get('MISP_BASE_URL', 'https://misp.local'),
                ':api_key' => (string) Env::get('MISP_API_KEY', 'your_misp_rest_api_key_here'),
                ':username' => null,
                ':password' => null,
                ':verify_ssl' => 0,
                ':last_status' => 'Siap (Mendukung REST API /events/restSearch & Simulasi)',
            ]);

            $stmt->execute([
                ':source_name' => 'Wazuh',
                ':base_url' => (string) Env::get('WAZUH_BASE_URL', 'https://wazuh.local:55000'),
                ':api_key' => null,
                ':username' => (string) Env::get('WAZUH_API_USER', 'wazuh-wui'),
                ':password' => (string) Env::get('WAZUH_API_PASSWORD', 'wazuh-password'),
                ':verify_ssl' => 0,
                ':last_status' => 'Siap (Mendukung Wazuh REST API /alerts & Simulasi)',
            ]);

            $stmt->execute([
                ':source_name' => 'Honeypot',
                ':base_url' => (string) Env::get('HONEYPOT_LOG_URL', 'http://honeypot.local:9000/logs'),
                ':api_key' => 'Cowrie / Amun JSON Sensor',
                ':username' => null,
                ':password' => null,
                ':verify_ssl' => 0,
                ':last_status' => 'Siap (Mendukung Cowrie/Amun JSON Stream & Simulasi)',
            ]);
        }
    }
}
