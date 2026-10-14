<?php

namespace App\Http\Controllers;

use App\Services\MlServiceClient;
use App\Support\Database;

class DatasetController
{
    public function overview(): array
    {
        $pdo = Database::connection();
        $totalCount = (int) $pdo->query("SELECT COUNT(*) FROM threats")->fetchColumn();

        // Auto-seed initial dataset if database is empty on first boot
        if ($totalCount === 0) {
            try {
                $this->seedDataset(['total_samples' => 12500, 'reset_existing' => true]);
                $totalCount = (int) $pdo->query("SELECT COUNT(*) FROM threats")->fetchColumn();
            } catch (\Throwable $e) {
                // Ignore if ML service is still booting
            }
        }

        $threatCount = (int) $pdo->query("SELECT COUNT(*) FROM threats WHERE label IN ('1', '+1', 'threat', 'Threat')")->fetchColumn();
        $benignCount = $totalCount - $threatCount;

        $byPlatform = $pdo->query("
            SELECT source_platform, COUNT(*) as count
            FROM threats
            GROUP BY source_platform
            ORDER BY count DESC
        ")->fetchAll();

        $byAttackType = $pdo->query("
            SELECT COALESCE(attack_type, 'Missing/Unknown') as attack_type, COUNT(*) as count
            FROM threats
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 8
        ")->fetchAll();

        $byProtocol = $pdo->query("
            SELECT UPPER(COALESCE(protocol, 'TCP')) as protocol, COUNT(*) as count
            FROM threats
            GROUP BY UPPER(COALESCE(protocol, 'TCP'))
            ORDER BY count DESC
        ")->fetchAll();

        $latestRun = $pdo->query("SELECT * FROM svm_training_runs ORDER BY id DESC LIMIT 1")->fetch();
        $sources = $pdo->query("SELECT * FROM cti_source_configs ORDER BY id ASC")->fetchAll();
        $predictionsCount = (int) $pdo->query("SELECT COUNT(*) FROM honeypot_predictions")->fetchColumn();
        $predictedThreatsCount = (int) $pdo->query("SELECT COUNT(*) FROM honeypot_predictions WHERE predicted_label = 1")->fetchColumn();

        return [
            'dataset_summary' => [
                'total_samples' => $totalCount,
                'threat_count' => $threatCount,
                'benign_count' => $benignCount,
                'by_platform' => $byPlatform,
                'by_attack_type' => $byAttackType,
                'by_protocol' => $byProtocol,
            ],
            'latest_svm_run' => $latestRun ?: null,
            'predictions_summary' => [
                'total_predictions' => $predictionsCount,
                'predicted_threats' => $predictedThreatsCount,
                'predicted_benign' => $predictionsCount - $predictedThreatsCount,
            ],
            'sources' => $sources,
        ];
    }

    public function seedDataset(array $body): array
    {
        $totalSamples = max(50, min(20000, (int) ($body['total_samples'] ?? 12500)));
        $resetExisting = (bool) ($body['reset_existing'] ?? true);

        $mlClient = new MlServiceClient();
        $generated = $mlClient->post('/api/ml/generate-dataset', [
            'total_samples' => $totalSamples,
            'include_dirty_samples' => true,
            'seed' => 42,
        ]);

        $records = $generated['records'] ?? [];
        $pdo = Database::connection();

        if ($resetExisting) {
            $pdo->exec("DELETE FROM threats");
        }

        $inserted = CtiSourceController::insertThreatRecords($pdo, $records, 'Honeypot');

        // Update source sync counts proportionally
        $now = date('Y-m-d H:i:s');
        $pdo->exec("
            UPDATE cti_source_configs
            SET last_sync_at = '{$now}',
                last_status = 'Tersinkronisasi (Dataset CTI Aktif)'
        ");

        return [
            'message' => "Dataset CTI berhasil di-generate ({$inserted} sampel termasuk data MISP, Wazuh, dan Honeypot).",
            'inserted_count' => $inserted,
        ];
    }

    public function listDataset(array $query): array
    {
        $limit = max(10, min(200, (int) ($query['limit'] ?? 50)));
        $offset = max(0, (int) ($query['offset'] ?? 0));
        $platform = trim((string) ($query['platform'] ?? ''));

        $pdo = Database::connection();
        if ($platform !== '' && $platform !== 'ALL') {
            $stmt = $pdo->prepare("SELECT * FROM threats WHERE source_platform = :p ORDER BY id ASC LIMIT :lim OFFSET :off");
            $stmt->bindValue(':p', $platform);
            $stmt->bindValue(':lim', $limit, \PDO::PARAM_INT);
            $stmt->bindValue(':off', $offset, \PDO::PARAM_INT);
            $stmt->execute();
            $rows = $stmt->fetchAll();

            $cntStmt = $pdo->prepare("SELECT COUNT(*) FROM threats WHERE source_platform = :p");
            $cntStmt->execute([':p' => $platform]);
            $total = (int) $cntStmt->fetchColumn();
        } else {
            $stmt = $pdo->prepare("SELECT * FROM threats ORDER BY id ASC LIMIT :lim OFFSET :off");
            $stmt->bindValue(':lim', $limit, \PDO::PARAM_INT);
            $stmt->bindValue(':off', $offset, \PDO::PARAM_INT);
            $stmt->execute();
            $rows = $stmt->fetchAll();
            $total = (int) $pdo->query("SELECT COUNT(*) FROM threats")->fetchColumn();
        }

        return [
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset,
            'records' => $rows,
        ];
    }

    public function runPreprocessing(array $body): array
    {
        $threshold = (float) ($body['correlation_threshold'] ?? 0.92);
        $pdo = Database::connection();
        $rows = $pdo->query("SELECT * FROM threats ORDER BY id ASC LIMIT 15000")->fetchAll();

        $mlClient = new MlServiceClient();
        $result = $mlClient->post('/api/ml/preprocess', [
            'records' => !empty($rows) ? $rows : null,
            'correlation_threshold' => $threshold,
        ]);

        $thesisTables = $mlClient->get('/api/ml/thesis-tables');
        $result['thesis_showcase'] = $thesisTables;

        return $result;
    }
}
