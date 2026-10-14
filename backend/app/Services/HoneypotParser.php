<?php

namespace App\Services;

/**
 * Honeypot (Cowrie & Amun) Log Parser and Connector
 * Ref: Figure 1.3 (page 6), Section 2.4 (page 34), and Section 4.4.2 (page 78) of thesis.pdf
 */
class HoneypotParser
{
    public function fetchLogs(
        string $logUrl,
        int $limit = 50,
        bool $allowSimulationFallback = true
    ): array {
        $cleanUrl = trim($logUrl);
        $isPlaceholder = $cleanUrl === '' || str_contains($cleanUrl, 'honeypot.local');

        if (!$isPlaceholder) {
            $ch = curl_init($cleanUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
            ]);
            $resp = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($resp !== false && $httpCode >= 200 && $httpCode < 300) {
                $records = $this->parseRawContent((string) $resp);
                return [
                    'mode' => 'LIVE_HONEYPOT_SENSOR',
                    'endpoint' => $cleanUrl,
                    'count' => count($records),
                    'records' => array_slice($records, 0, $limit),
                ];
            }
        }

        if (!$allowSimulationFallback) {
            return [
                'mode' => 'ERROR',
                'endpoint' => $cleanUrl,
                'count' => 0,
                'records' => [],
            ];
        }

        $mlClient = new MlServiceClient();
        $gen = $mlClient->post('/api/ml/generate-dataset', [
            'total_samples' => $limit,
            'include_dirty_samples' => false,
            'source_filter' => 'Honeypot',
            'seed' => random_int(1, 9999),
        ]);

        return [
            'mode' => 'SIMULATED_COWRIE_AMUN_HONEYPOT',
            'endpoint' => $cleanUrl,
            'count' => count($gen['records'] ?? []),
            'records' => $gen['records'] ?? [],
        ];
    }

    /**
     * Parses JSON array, JSON Lines (NDJSON from Cowrie/Amun as in Figure 1.3), or CSV content.
     */
    public function parseRawContent(string $rawContent): array
    {
        $trimmed = trim($rawContent);
        if ($trimmed === '') {
            return [];
        }

        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            $items = isset($decoded[0]) ? $decoded : ($decoded['records'] ?? $decoded['logs'] ?? [$decoded]);
            return array_map([$this, 'normalizeLogEntry'], $items);
        }

        // Try JSON Lines (Cowrie / Amun format in Figure 1.3) or CSV
        $lines = preg_split('/\r\n|\r|\n/', $trimmed);
        $firstLine = trim($lines[0] ?? '');

        if (str_starts_with($firstLine, '{')) {
            $records = [];
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                $obj = json_decode($line, true);
                if (is_array($obj)) {
                    $records[] = $this->normalizeLogEntry($obj);
                }
            }
            return $records;
        }

        // Parse as CSV
        $rows = array_map('str_getcsv', $lines);
        if (count($rows) < 2) {
            return [];
        }
        $headers = array_map(fn($h) => strtolower(trim((string) $h)), array_shift($rows));
        $records = [];
        foreach ($rows as $row) {
            if (count($row) < count($headers)) {
                continue;
            }
            $assoc = array_combine($headers, array_slice($row, 0, count($headers)));
            if (is_array($assoc)) {
                $records[] = $this->normalizeLogEntry($assoc);
            }
        }
        return $records;
    }

    public function normalizeLogEntry(array $entry): array
    {
        $srcIp = trim((string) ($entry['source_ip'] ?? $entry['src_ip'] ?? $entry['ip'] ?? '68.183.55.117'));
        $dstIp = trim((string) ($entry['dest_ip'] ?? $entry['dst_ip'] ?? '68.183.44.135'));
        $srcPort = (int) ($entry['src_port'] ?? 57368);
        $dstPort = $entry['port'] ?? $entry['dest_port'] ?? $entry['dst_port'] ?? 22;
        $proto = (string) ($entry['protocol'] ?? $entry['transport'] ?? 'TCP');
        $payload = $entry['payload_size'] ?? 1024;
        $sig = (string) ($entry['signature'] ?? $entry['description'] ?? 'Connection to Honeypot');
        $atkType = $entry['attack_type'] ?? null;

        if ($atkType === null || $atkType === '') {
            $sigLower = strtolower($sig);
            if (str_contains($sigLower, 'ssh') || isset($entry['ssh_username']) || isset($entry['ssh_version'])) {
                $atkType = 'SSH Brute Force';
            } elseif (str_contains($sigLower, 'dns')) {
                $atkType = 'DNS Flood';
            } elseif (str_contains($sigLower, 'ddos')) {
                $atkType = 'DDoS';
            } elseif (str_contains($sigLower, 'sql')) {
                $atkType = 'SQL Injection';
            } elseif (strtolower((string) ($entry['severity'] ?? 'high')) === 'low') {
                $atkType = 'Normal';
            } else {
                $atkType = 'Malware Payload';
            }
        }

        $severity = strtolower((string) ($entry['severity'] ?? 'high'));
        $label = $entry['label'] ?? ($severity === 'low' || strtolower((string) $atkType) === 'normal' ? -1 : 1);

        return [
            'event_id' => (string) ($entry['event_id'] ?? ('HNY-' . uniqid())),
            'timestamp' => $entry['timestamp'] ?? date('Y-m-d H:i:s'),
            'source_ip' => $srcIp,
            'dest_ip' => $dstIp,
            'src_port' => $srcPort,
            'port' => $dstPort,
            'protocol' => $proto,
            'payload_size' => $payload,
            'attack_type' => $atkType,
            'domain_name' => (string) ($entry['domain_name'] ?? 'circl.lu'),
            'file_hash' => (string) ($entry['file_hash'] ?? $entry['sensor'] ?? 'e2abd414-f3b6-11eb-8572-9ddcd2a483fc'),
            'file_hash_score' => (float) ($entry['file_hash_score'] ?? ($label == 1 ? 85.0 : 10.0)),
            'ip_reputation_score' => (float) ($entry['ip_reputation_score'] ?? ($label == 1 ? 89.5 : 12.0)),
            'attack_frequency' => (int) ($entry['attack_frequency'] ?? ($label == 1 ? 40 : 2)),
            'ids_type' => (string) ($entry['ids_type'] ?? 'network'),
            'source_platform' => (string) ($entry['source_platform'] ?? 'Honeypot'),
            'description' => $sig,
            'label' => $label,
        ];
    }
}
