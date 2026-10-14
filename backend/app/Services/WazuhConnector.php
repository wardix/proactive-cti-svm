<?php

namespace App\Services;

/**
 * Wazuh SIEM & Intrusion Detection System (IDS) Connector
 * Ref: Section 2.5 (page 36-37) and Chapter 3 (page 53-56) of thesis.pdf
 */
class WazuhConnector
{
    /**
     * Authenticates with Wazuh REST API (POST /security/user/authenticate)
     * and pulls security alerts / IDS rules, with simulation fallback.
     */
    public function fetchAlerts(
        string $baseUrl,
        string $username,
        string $password,
        int $limit = 50,
        bool $verifySsl = false,
        bool $allowSimulationFallback = true
    ): array {
        $cleanUrl = rtrim($baseUrl, '/');
        $authEndpoint = $cleanUrl . '/security/user/authenticate';
        $alertsEndpoint = $cleanUrl . '/alerts?limit=' . $limit;

        $isPlaceholder = str_contains($cleanUrl, 'wazuh.local')
            || $username === ''
            || $password === 'wazuh-password';

        if (!$isPlaceholder) {
            $ch = curl_init($authEndpoint);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_USERPWD => "{$username}:{$password}",
                CURLOPT_TIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => $verifySsl,
                CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
            ]);
            $authResp = curl_exec($ch);
            $authCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($authResp !== false && $authCode >= 200 && $authCode < 300) {
                $authJson = json_decode((string) $authResp, true);
                $jwtToken = $authJson['data']['token'] ?? null;

                if ($jwtToken) {
                    $ch2 = curl_init($alertsEndpoint);
                    curl_setopt_array($ch2, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_TIMEOUT => 12,
                        CURLOPT_SSL_VERIFYPEER => $verifySsl,
                        CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
                        CURLOPT_HTTPHEADER => [
                            "Authorization: Bearer {$jwtToken}",
                            'Accept: application/json',
                        ],
                    ]);
                    $alertsResp = curl_exec($ch2);
                    $alertsCode = (int) curl_getinfo($ch2, CURLINFO_HTTP_CODE);
                    curl_close($ch2);

                    if ($alertsResp !== false && $alertsCode >= 200 && $alertsCode < 300) {
                        $decoded = json_decode((string) $alertsResp, true);
                        if (is_array($decoded)) {
                            $records = $this->parseWazuhAlerts($decoded);
                            return [
                                'mode' => 'LIVE_WAZUH_API',
                                'endpoint' => $alertsEndpoint,
                                'count' => count($records),
                                'records' => $records,
                            ];
                        }
                    }
                }
            }
        }

        if (!$allowSimulationFallback) {
            return [
                'mode' => 'ERROR',
                'endpoint' => $alertsEndpoint,
                'count' => 0,
                'records' => [],
            ];
        }

        $mlClient = new MlServiceClient();
        $gen = $mlClient->post('/api/ml/generate-dataset', [
            'total_samples' => $limit,
            'include_dirty_samples' => false,
            'source_filter' => 'Wazuh',
            'seed' => random_int(1, 9999),
        ]);

        return [
            'mode' => 'SIMULATED_WAZUH_SIEM_ALERTS',
            'endpoint' => $alertsEndpoint,
            'count' => count($gen['records'] ?? []),
            'records' => $gen['records'] ?? [],
        ];
    }

    /**
     * Parses Wazuh alerts.json / API items into standardized CTI tabular rows.
     */
    public function parseWazuhAlerts(array $data): array
    {
        $items = $data['data']['affected_items'] ?? ($data['alerts'] ?? (isset($data[0]) ? $data : [$data]));
        $records = [];

        foreach ($items as $alert) {
            if (!is_array($alert)) {
                continue;
            }
            $rule = $alert['rule'] ?? [];
            $dataBlock = $alert['data'] ?? [];
            $level = (int) ($rule['level'] ?? 7);
            $description = (string) ($rule['description'] ?? $alert['full_log'] ?? 'Wazuh IDS Alert');
            $srcIp = (string) ($dataBlock['srcip'] ?? $alert['src_ip'] ?? $alert['source_ip'] ?? '198.51.100.7');
            $dstPort = (int) ($dataBlock['dstport'] ?? $alert['port'] ?? 22);
            $proto = strtoupper((string) ($dataBlock['protocol'] ?? $alert['protocol'] ?? 'TCP'));
            $timestamp = isset($alert['timestamp'])
                ? substr(str_replace('T', ' ', (string) $alert['timestamp']), 0, 19)
                : date('Y-m-d H:i:s');

            $isThreat = $level >= 7 ? 1 : -1;
            $attackType = 'Normal';
            if ($isThreat === 1) {
                $descLower = strtolower($description);
                if (str_contains($descLower, 'ssh') || str_contains($descLower, 'brute')) {
                    $attackType = 'SSH Brute Force';
                } elseif (str_contains($descLower, 'dns')) {
                    $attackType = 'DNS Flood';
                } elseif (str_contains($descLower, 'sql')) {
                    $attackType = 'SQL Injection';
                } elseif (str_contains($descLower, 'ddos') || str_contains($descLower, 'flood')) {
                    $attackType = 'DDoS';
                } else {
                    $attackType = 'Malware Payload';
                }
            }

            $records[] = [
                'event_id' => 'WZH-' . ($alert['id'] ?? $rule['id'] ?? uniqid()),
                'timestamp' => $timestamp,
                'source_ip' => $srcIp,
                'dest_ip' => (string) ($alert['agent']['ip'] ?? '68.183.44.135'),
                'src_port' => (int) ($dataBlock['srcport'] ?? 51200),
                'port' => $dstPort,
                'protocol' => in_array($proto, ['TCP', 'UDP', 'ICMP'], true) ? $proto : 'TCP',
                'payload_size' => (float) ($alert['payload_size'] ?? ($isThreat === 1 ? 1024 : 256)),
                'attack_type' => $attackType,
                'domain_name' => 'wazuh-monitored.local',
                'file_hash' => (string) ($alert['syscheck']['md5_after'] ?? 'none'),
                'file_hash_score' => $isThreat === 1 ? 78.5 : 8.0,
                'ip_reputation_score' => $isThreat === 1 ? min(99.0, $level * 7.5) : 12.0,
                'attack_frequency' => (int) ($rule['firedtimes'] ?? ($isThreat === 1 ? 35 : 2)),
                'ids_type' => 'network',
                'source_platform' => 'Wazuh',
                'description' => $description,
                'label' => $isThreat,
            ];
        }

        return $records;
    }
}
