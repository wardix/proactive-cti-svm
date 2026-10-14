<?php

namespace App\Services;

/**
 * MISP (Malware Information Sharing Platform) REST API Connector
 * Ref: Section 2.6, Figure 3.3 (page 57), and Section 4.4.2 (page 76-78) of thesis.pdf
 */
class MispConnector
{
    /**
     * Fetches events from MISP REST API: POST {baseUrl}/events/restSearch
     * If live MISP server is unreachable or configured with placeholder host,
     * returns parsed MISP events from fallback generator or throws if simulation=false.
     */
    public function fetchEvents(
        string $baseUrl,
        string $apiKey,
        int $limit = 50,
        bool $verifySsl = false,
        bool $allowSimulationFallback = true
    ): array {
        $cleanUrl = rtrim($baseUrl, '/');
        $endpoint = str_ends_with($cleanUrl, '/events/restSearch')
            ? $cleanUrl
            : $cleanUrl . '/events/restSearch';

        $isPlaceholder = str_contains($cleanUrl, 'misp.local')
            || $apiKey === ''
            || $apiKey === 'your_misp_rest_api_key_here';

        if (!$isPlaceholder) {
            $payload = json_encode([
                'returnFormat' => 'json',
                'limit' => $limit,
            ]);

            $ch = curl_init($endpoint);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_TIMEOUT => 12,
                CURLOPT_SSL_VERIFYPEER => $verifySsl,
                CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
                CURLOPT_HTTPHEADER => [
                    "Authorization: {$apiKey}",
                    'Accept: application/json',
                    'Content-Type: application/json',
                ],
            ]);

            $response = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response !== false && $httpCode >= 200 && $httpCode < 300) {
                $decoded = json_decode((string) $response, true);
                if (is_array($decoded)) {
                    $records = $this->parseMispResponse($decoded);
                    return [
                        'mode' => 'LIVE_MISP_API',
                        'endpoint' => $endpoint,
                        'count' => count($records),
                        'records' => $records,
                    ];
                }
            }
        }

        if (!$allowSimulationFallback) {
            return [
                'mode' => 'ERROR',
                'endpoint' => $endpoint,
                'count' => 0,
                'records' => [],
            ];
        }

        // Fallback via Python ML Service generator filtered for MISP + Figure 3.3 structure
        $mlClient = new MlServiceClient();
        $gen = $mlClient->post('/api/ml/generate-dataset', [
            'total_samples' => $limit,
            'include_dirty_samples' => false,
            'source_filter' => 'MISP',
            'seed' => random_int(1, 9999),
        ]);

        return [
            'mode' => 'SIMULATED_MISP_REST_FEED',
            'endpoint' => $endpoint,
            'count' => count($gen['records'] ?? []),
            'records' => $gen['records'] ?? [],
        ];
    }

    /**
     * Parses MISP JSON structure (Figure 3.3 on page 57 & Section 4.4.2 on page 77)
     * into standardized CTI tabular rows.
     */
    public function parseMispResponse(array $data): array
    {
        $events = $data['response'] ?? ($data['Event'] ? [['Event' => $data['Event']]] : [$data]);
        $records = [];

        foreach ($events as $item) {
            $event = $item['Event'] ?? $item;
            $eventId = 'MISP-' . ($event['id'] ?? $event['uuid'] ?? uniqid());
            $info = (string) ($event['info'] ?? $event['description'] ?? 'MISP Threat Event');
            $threatLevel = (int) ($event['threat_level_id'] ?? 1); // 1=High, 2=Medium, 3=Low, 4=Undefined
            $attributes = $event['Attribute'] ?? [];

            $srcIp = '149.13.33.14';
            $dstPort = 443;
            $domain = 'circl.lu';
            $fileHash = '91ae0a21-c7ae-4c7f-b84b-b84a7ce53d1f';
            $timestamp = isset($event['timestamp']) && is_numeric($event['timestamp'])
                ? date('Y-m-d H:i:s', (int) $event['timestamp'])
                : date('Y-m-d H:i:s');
            $toIds = true;

            foreach ($attributes as $attr) {
                $type = (string) ($attr['type'] ?? '');
                $val = (string) ($attr['value'] ?? '');
                if (in_array($type, ['ip-src', 'ip-dst', 'ip'], true) && $val !== '') {
                    $srcIp = $val;
                } elseif ($type === 'port' && is_numeric($val)) {
                    $dstPort = (int) $val;
                } elseif (in_array($type, ['domain', 'hostname'], true) && $val !== '') {
                    $domain = $val;
                } elseif (in_array($type, ['md5', 'sha1', 'sha256'], true) && $val !== '') {
                    $fileHash = $val;
                } elseif ($type === 'datetime' && $val !== '') {
                    $timestamp = str_replace(['T', 'Z'], [' ', ''], $val);
                }
                if (isset($attr['to_ids'])) {
                    $toIds = (bool) $attr['to_ids'];
                }
            }

            $isThreat = ($threatLevel <= 2 || $toIds) ? 1 : -1;
            $records[] = [
                'event_id' => $eventId,
                'timestamp' => $timestamp,
                'source_ip' => $srcIp,
                'dest_ip' => '68.183.44.135',
                'src_port' => random_int(40000, 62000),
                'port' => $dstPort,
                'protocol' => $dstPort === 53 ? 'UDP' : 'TCP',
                'payload_size' => $isThreat === 1 ? 1420 : 320,
                'attack_type' => $isThreat === 1 ? 'Malware Payload' : 'Normal',
                'domain_name' => $domain,
                'file_hash' => $fileHash,
                'file_hash_score' => $isThreat === 1 ? 88.0 : 12.0,
                'ip_reputation_score' => $isThreat === 1 ? 91.0 : 14.0,
                'attack_frequency' => $isThreat === 1 ? 45 : 3,
                'ids_type' => 'network',
                'source_platform' => 'MISP',
                'description' => $info,
                'label' => $isThreat,
            ];
        }

        return $records;
    }
}
