<?php

namespace App\Http\Controllers;

use App\Services\MlServiceClient;
use App\Support\Database;

class SvmController
{
    public function train(array $body): array
    {
        $kernel = strtolower(trim((string) ($body['kernel'] ?? 'rbf')));
        $cParam = max(0.01, (float) ($body['c_param'] ?? 1.0));
        $gammaParam = trim((string) ($body['gamma_param'] ?? 'scale'));
        $trainRatio = max(0.50, min(0.95, (float) ($body['train_ratio'] ?? 0.80)));
        $corrThreshold = max(0.50, min(1.0, (float) ($body['correlation_threshold'] ?? 0.92)));

        $pdo = Database::connection();
        $rows = $pdo->query("SELECT * FROM threats ORDER BY id ASC LIMIT 15000")->fetchAll();

        $mlClient = new MlServiceClient();
        $result = $mlClient->post('/api/ml/train', [
            'records' => !empty($rows) ? $rows : null,
            'total_samples_if_empty' => 12500,
            'kernel' => $kernel,
            'c_param' => $cParam,
            'gamma_param' => $gammaParam,
            'train_ratio' => $trainRatio,
            'correlation_threshold' => $corrThreshold,
        ]);

        $split = $result['dataset_split'] ?? [];
        $metrics = $result['metrics'] ?? [];
        $cm = $result['confusion_matrix'] ?? [];
        $internals = $result['svm_internals'] ?? [];

        $stmt = $pdo->prepare("
            INSERT INTO svm_training_runs (
                kernel, c_param, gamma_param, train_ratio,
                total_samples, train_samples, test_samples,
                threat_count, benign_count, support_vectors_count,
                accuracy, precision_score, recall_score, f1_score, auc_score,
                tp, tn, fp, fn,
                selected_features_json, confusion_matrix_json, roc_curve_json, preprocessing_summary_json
            ) VALUES (
                :kernel, :c_param, :gamma_param, :train_ratio,
                :total_samples, :train_samples, :test_samples,
                :threat_count, :benign_count, :support_vectors_count,
                :accuracy, :precision_score, :recall_score, :f1_score, :auc_score,
                :tp, :tn, :fp, :fn,
                :selected_features_json, :confusion_matrix_json, :roc_curve_json, :preprocessing_summary_json
            )
        ");

        $stmt->execute([
            ':kernel' => $kernel,
            ':c_param' => $cParam,
            ':gamma_param' => $gammaParam,
            ':train_ratio' => $trainRatio,
            ':total_samples' => (int) ($split['total_clean_samples'] ?? 0),
            ':train_samples' => (int) ($split['train_samples'] ?? 0),
            ':test_samples' => (int) ($split['test_samples'] ?? 0),
            ':threat_count' => (int) ($split['threat_count'] ?? 0),
            ':benign_count' => (int) ($split['benign_count'] ?? 0),
            ':support_vectors_count' => (int) ($internals['support_vectors_count'] ?? 0),
            ':accuracy' => (float) ($metrics['accuracy'] ?? 0.0),
            ':precision_score' => (float) ($metrics['precision'] ?? 0.0),
            ':recall_score' => (float) ($metrics['recall'] ?? 0.0),
            ':f1_score' => (float) ($metrics['f1_score'] ?? 0.0),
            ':auc_score' => (float) ($metrics['auc'] ?? 0.0),
            ':tp' => (int) ($cm['tp'] ?? 0),
            ':tn' => (int) ($cm['tn'] ?? 0),
            ':fp' => (int) ($cm['fp'] ?? 0),
            ':fn' => (int) ($cm['fn'] ?? 0),
            ':selected_features_json' => json_encode($result['feature_selection_report'] ?? []),
            ':confusion_matrix_json' => json_encode($cm),
            ':roc_curve_json' => json_encode($result['roc_curve'] ?? []),
            ':preprocessing_summary_json' => json_encode($result['preprocessing_report'] ?? []),
        ]);

        return $result;
    }

    public function history(): array
    {
        $pdo = Database::connection();
        $runs = $pdo->query("SELECT * FROM svm_training_runs ORDER BY id DESC LIMIT 10")->fetchAll();

        if (empty($runs)) {
            $this->train([
                'kernel' => 'rbf',
                'c_param' => 1.0,
                'gamma_param' => 'scale',
                'train_ratio' => 0.80,
            ]);
            $runs = $pdo->query("SELECT * FROM svm_training_runs ORDER BY id DESC LIMIT 10")->fetchAll();
        }

        foreach ($runs as &$run) {
            $run['selected_features'] = json_decode((string) ($run['selected_features_json'] ?? '{}'), true);
            $run['confusion_matrix'] = json_decode((string) ($run['confusion_matrix_json'] ?? '{}'), true);
            $run['roc_curve'] = json_decode((string) ($run['roc_curve_json'] ?? '[]'), true);
            $run['preprocessing_summary'] = json_decode((string) ($run['preprocessing_summary_json'] ?? '{}'), true);
            unset(
                $run['selected_features_json'],
                $run['confusion_matrix_json'],
                $run['roc_curve_json'],
                $run['preprocessing_summary_json']
            );
        }

        $mlClient = new MlServiceClient();
        $thesisInfo = $mlClient->get('/api/ml/thesis-tables');

        return [
            'latest_run' => $runs[0] ?? null,
            'history' => $runs,
            'mathematical_formulation' => $thesisInfo['mathematical_formulation'] ?? [],
        ];
    }

    public function predict(array $body): array
    {
        $records = $body['records'] ?? [];
        if (empty($records) && isset($body['source_ip'])) {
            $records = [$body];
        }
        if (empty($records)) {
            return ['error' => 'Tidak ada data untuk diprediksi.'];
        }

        $mlClient = new MlServiceClient();
        $result = $mlClient->post('/api/ml/predict', ['records' => $records]);
        $predictions = $result['predictions'] ?? [];

        $pdo = Database::connection();
        self::savePredictions($pdo, $predictions);

        return [
            'message' => 'Prediksi SVM selesai untuk ' . count($predictions) . ' data.',
            'result' => $result,
            'stored_predictions' => $this->listPredictions()['predictions'],
        ];
    }

    public function predictHoneypotBatch(array $body): array
    {
        $count = max(1, min(50, (int) ($body['count'] ?? 12)));
        $mlClient = new MlServiceClient();
        $generated = $mlClient->get('/api/ml/generate-honeypot-logs', ['count' => $count]);
        $logs = $generated['logs'] ?? [];

        $predResp = $mlClient->post('/api/ml/predict', ['records' => $logs]);
        $predictions = $predResp['predictions'] ?? [];

        $pdo = Database::connection();
        self::savePredictions($pdo, $predictions);

        return [
            'message' => "Berhasil menarik {$count} log baru dari Honeypot (Cowrie/Amun) dan mengklasifikasikannya dengan SVM.",
            'result' => $predResp,
            'stored_predictions' => $this->listPredictions()['predictions'],
        ];
    }

    public function listPredictions(): array
    {
        $pdo = Database::connection();
        $rows = $pdo->query("SELECT * FROM honeypot_predictions ORDER BY id DESC LIMIT 100")->fetchAll();

        if (empty($rows)) {
            try {
                $mlClient = new MlServiceClient();
                $generated = $mlClient->get('/api/ml/generate-honeypot-logs', ['count' => 12]);
                $predResp = $mlClient->post('/api/ml/predict', ['records' => $generated['logs'] ?? []]);
                self::savePredictions($pdo, $predResp['predictions'] ?? []);
                $rows = $pdo->query("SELECT * FROM honeypot_predictions ORDER BY id DESC LIMIT 100")->fetchAll();
            } catch (\Throwable $e) {
                // Ignore if ML service not ready
            }
        }

        $threatCount = 0;
        $benignCount = 0;
        foreach ($rows as &$r) {
            if ((int) $r['predicted_label'] === 1) {
                $threatCount++;
            } else {
                $benignCount++;
            }
            $r['raw_log'] = json_decode((string) ($r['raw_log_json'] ?? '{}'), true);
            unset($r['raw_log_json']);
        }

        return [
            'total' => count($rows),
            'threat_count' => $threatCount,
            'benign_count' => $benignCount,
            'predictions' => $rows,
        ];
    }

    private static function savePredictions(\PDO $pdo, array $predictions): void
    {
        $stmt = $pdo->prepare("
            INSERT INTO honeypot_predictions (
                timestamp, source_ip, dest_ip, src_port, port,
                protocol, payload_size, attack_type, honeypot_sensor,
                domain_name, file_hash, ip_reputation_score, attack_frequency,
                file_hash_score, predicted_label, confidence_score, decision_value, raw_log_json
            ) VALUES (
                :timestamp, :source_ip, :dest_ip, :src_port, :port,
                :protocol, :payload_size, :attack_type, :honeypot_sensor,
                :domain_name, :file_hash, :ip_reputation_score, :attack_frequency,
                :file_hash_score, :predicted_label, :confidence_score, :decision_value, :raw_log_json
            )
        ");

        foreach ($predictions as $p) {
            $stmt->execute([
                ':timestamp' => (string) ($p['timestamp'] ?? date('Y-m-d H:i:s')),
                ':source_ip' => (string) ($p['source_ip'] ?? '0.0.0.0'),
                ':dest_ip' => (string) ($p['dest_ip'] ?? '68.183.44.135'),
                ':src_port' => (int) ($p['src_port'] ?? 57368),
                ':port' => (int) ($p['port'] ?? 22),
                ':protocol' => strtoupper((string) ($p['protocol'] ?? 'TCP')),
                ':payload_size' => (float) ($p['payload_size'] ?? 0.0),
                ':attack_type' => (string) ($p['attack_type'] ?? 'SSH Brute Force'),
                ':honeypot_sensor' => (string) ($p['vendor_product'] ?? $p['honeypot_sensor'] ?? 'Cowrie'),
                ':domain_name' => (string) ($p['domain_name'] ?? 'circl.lu'),
                ':file_hash' => (string) ($p['file_hash'] ?? 'e2abd414-f3b6-11eb-8572-9ddcd2a483fc'),
                ':ip_reputation_score' => (float) ($p['ip_reputation_score'] ?? 50.0),
                ':attack_frequency' => (int) ($p['attack_frequency'] ?? 1),
                ':file_hash_score' => (float) ($p['file_hash_score'] ?? 0.0),
                ':predicted_label' => (int) ($p['predicted_label'] ?? 1),
                ':confidence_score' => (float) ($p['confidence_score'] ?? 95.0),
                ':decision_value' => (float) ($p['decision_value'] ?? 1.0),
                ':raw_log_json' => json_encode($p),
            ]);
        }
    }
}
