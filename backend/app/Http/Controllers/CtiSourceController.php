<?php

namespace App\Http\Controllers;

use App\Services\HoneypotParser;
use App\Services\MispConnector;
use App\Services\WazuhConnector;
use App\Support\Database;
use PDO;

class CtiSourceController
{
    public function index(): array
    {
        $pdo = Database::connection();
        $sources = $pdo->query("SELECT * FROM cti_source_configs ORDER BY id ASC")->fetchAll();
        return [
            'sources' => $sources,
        ];
    }

    public function updateConfig(array $body): array
    {
        $sourceName = trim((string) ($body['source_name'] ?? ''));
        if (!in_array($sourceName, ['MISP', 'Wazuh', 'Honeypot'], true)) {
            return ['error' => 'Source name harus MISP, Wazuh, atau Honeypot'];
        }

        $pdo = Database::connection();
        $stmt = $pdo->prepare("
            UPDATE cti_source_configs
            SET base_url = :base_url,
                api_key = :api_key,
                username = :username,
                password = :password,
                verify_ssl = :verify_ssl,
                updated_at = CURRENT_TIMESTAMP
            WHERE source_name = :source_name
        ");
        $stmt->execute([
            ':base_url' => (string) ($body['base_url'] ?? ''),
            ':api_key' => (string) ($body['api_key'] ?? ''),
            ':username' => (string) ($body['username'] ?? ''),
            ':password' => (string) ($body['password'] ?? ''),
            ':verify_ssl' => !empty($body['verify_ssl']) ? 1 : 0,
            ':source_name' => $sourceName,
        ]);

        return [
            'message' => "Konfigurasi {$sourceName} berhasil disimpan.",
            'sources' => $this->index()['sources'],
        ];
    }

    public function pullFromSource(array $body): array
    {
        $sourceName = trim((string) ($body['source_name'] ?? 'MISP'));
        $limit = max(5, min(2000, (int) ($body['limit'] ?? 100)));

        $pdo = Database::connection();
        $stmt = $pdo->prepare("SELECT * FROM cti_source_configs WHERE source_name = :name LIMIT 1");
        $stmt->execute([':name' => $sourceName]);
        $cfg = $stmt->fetch();

        if (!$cfg) {
            return ['error' => "Sumber data {$sourceName} tidak ditemukan."];
        }

        if ($sourceName === 'MISP') {
            $connector = new MispConnector();
            $result = $connector->fetchEvents(
                (string) $cfg['base_url'],
                (string) $cfg['api_key'],
                $limit,
                (bool) $cfg['verify_ssl'],
                true
            );
        } elseif ($sourceName === 'Wazuh') {
            $connector = new WazuhConnector();
            $result = $connector->fetchAlerts(
                (string) $cfg['base_url'],
                (string) $cfg['username'],
                (string) $cfg['password'],
                $limit,
                (bool) $cfg['verify_ssl'],
                true
            );
        } else {
            $parser = new HoneypotParser();
            $result = $parser->fetchLogs((string) $cfg['base_url'], $limit, true);
        }

        $records = $result['records'] ?? [];
        $inserted = self::insertThreatRecords($pdo, $records, $sourceName);

        $now = date('Y-m-d H:i:s');
        $upd = $pdo->prepare("
            UPDATE cti_source_configs
            SET last_sync_at = :sync_at,
                last_sync_count = :cnt,
                last_status = :status,
                updated_at = CURRENT_TIMESTAMP
            WHERE source_name = :name
        ");
        $upd->execute([
            ':sync_at' => $now,
            ':cnt' => $inserted,
            ':status' => "Sukses tarik {$inserted} data ({$result['mode']})",
            ':name' => $sourceName,
        ]);

        return [
            'message' => "Berhasil menarik {$inserted} baris data dari {$sourceName} ({$result['mode']}).",
            'mode' => $result['mode'],
            'inserted_count' => $inserted,
            'sample_records' => array_slice($records, 0, 5),
            'sources' => $this->index()['sources'],
        ];
    }

    public function uploadLogs(array $body): array
    {
        $rawContent = (string) ($body['content'] ?? '');
        $sourcePlatform = (string) ($body['source_platform'] ?? 'Honeypot');

        $parser = new HoneypotParser();
        $records = $parser->parseRawContent($rawContent);
        if (empty($records)) {
            return ['error' => 'Format file/konten tidak dapat diparsing. Gunakan format JSON, JSON Lines (Cowrie/Amun), atau CSV.'];
        }

        $pdo = Database::connection();
        $inserted = self::insertThreatRecords($pdo, $records, $sourcePlatform);

        return [
            'message' => "Berhasil mengimpor {$inserted} baris log ke dataset ({$sourcePlatform}).",
            'inserted_count' => $inserted,
            'sample_records' => array_slice($records, 0, 5),
        ];
    }

    public static function insertThreatRecords(PDO $pdo, array $records, string $defaultPlatform = 'Honeypot'): int
    {
        if (empty($records)) {
            return 0;
        }

        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare("
                INSERT INTO threats (
                    event_id, timestamp, source_ip, dest_ip, src_port, port,
                    protocol, payload_size, attack_type, domain_name, file_hash,
                    file_hash_score, ip_reputation_score, attack_frequency,
                    ids_type, source_platform, description, label, is_cleaned
                ) VALUES (
                    :event_id, :timestamp, :source_ip, :dest_ip, :src_port, :port,
                    :protocol, :payload_size, :attack_type, :domain_name, :file_hash,
                    :file_hash_score, :ip_reputation_score, :attack_frequency,
                    :ids_type, :source_platform, :description, :label, :is_cleaned
                )
            ");

            $count = 0;
            foreach ($records as $r) {
                $stmt->execute([
                    ':event_id' => $r['event_id'] ?? ('EVT-' . uniqid()),
                    ':timestamp' => $r['timestamp'] ?? null,
                    ':source_ip' => (string) ($r['source_ip'] ?? '0.0.0.0'),
                    ':dest_ip' => (string) ($r['dest_ip'] ?? '68.183.44.135'),
                    ':src_port' => (int) ($r['src_port'] ?? 51000),
                    ':port' => isset($r['port']) ? (string) $r['port'] : null,
                    ':protocol' => isset($r['protocol']) ? (string) $r['protocol'] : null,
                    ':payload_size' => isset($r['payload_size']) ? (string) $r['payload_size'] : null,
                    ':attack_type' => $r['attack_type'] ?? null,
                    ':domain_name' => (string) ($r['domain_name'] ?? 'circl.lu'),
                    ':file_hash' => (string) ($r['file_hash'] ?? 'none'),
                    ':file_hash_score' => (float) ($r['file_hash_score'] ?? 0.0),
                    ':ip_reputation_score' => (float) ($r['ip_reputation_score'] ?? 50.0),
                    ':attack_frequency' => (int) ($r['attack_frequency'] ?? 1),
                    ':ids_type' => (string) ($r['ids_type'] ?? 'network'),
                    ':source_platform' => (string) ($r['source_platform'] ?? $defaultPlatform),
                    ':description' => (string) ($r['description'] ?? ''),
                    ':label' => (string) ($r['label'] ?? '1'),
                    ':is_cleaned' => isset($r['is_cleaned']) ? (int) $r['is_cleaned'] : 1,
                ]);
                $count++;
            }
            $pdo->commit();
            return $count;
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }
}
