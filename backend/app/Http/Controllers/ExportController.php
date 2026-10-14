<?php

namespace App\Http\Controllers;

use App\Support\Database;

class ExportController
{
    /**
     * Generates Wazuh Custom XML Rules from SVM-detected Cyber Threats (predicted_label = 1)
     * Ref: Section 3.3 (Figure 3.6, page 68-69) of thesis.pdf
     */
    public function exportWazuhRules(): array
    {
        $pdo = Database::connection();
        $threats = $pdo->query("
            SELECT * FROM honeypot_predictions
            WHERE predicted_label = 1
            ORDER BY id DESC
            LIMIT 100
        ")->fetchAll();

        if (empty($threats)) {
            $threats = $pdo->query("
                SELECT * FROM threats
                WHERE label IN ('1', '+1', 'threat', 'Threat')
                ORDER BY id DESC
                LIMIT 25
            ")->fetchAll();
        }

        $xmlLines = [];
        $xmlLines[] = '<!-- ===================================================================== -->';
        $xmlLines[] = '<!-- Proactive CTI + SVM Defense Model - Wazuh IDS Custom Rules            -->';
        $xmlLines[] = '<!-- Generated at: ' . date('Y-m-d H:i:s') . '                                      -->';
        $xmlLines[] = '<!-- Total Detected Threat Rules: ' . count($threats) . '                                     -->';
        $xmlLines[] = '<!-- ===================================================================== -->';
        $xmlLines[] = '<group name="local,cti_svm_defense,proactive_block,">';

        $ruleId = 100500;
        $seenIps = [];

        foreach ($threats as $t) {
            $srcIp = htmlspecialchars((string) ($t['source_ip'] ?? '0.0.0.0'), ENT_XML1);
            if (isset($seenIps[$srcIp])) {
                continue;
            }
            $seenIps[$srcIp] = true;

            $port = (int) ($t['port'] ?? 22);
            $proto = strtolower(htmlspecialchars((string) ($t['protocol'] ?? 'tcp'), ENT_XML1));
            $atkType = htmlspecialchars((string) ($t['attack_type'] ?? 'Cyber Threat'), ENT_XML1);
            $sensor = htmlspecialchars((string) ($t['honeypot_sensor'] ?? 'Honeypot'), ENT_XML1);
            $conf = isset($t['confidence_score']) ? number_format((float) $t['confidence_score'], 2) : '95.00';

            $xmlLines[] = "  <rule id=\"{$ruleId}\" level=\"12\">";
            $xmlLines[] = "    <srcip>{$srcIp}</srcip>";
            $xmlLines[] = "    <dstport>{$port}</dstport>";
            $xmlLines[] = "    <protocol>{$proto}</protocol>";
            $xmlLines[] = "    <description>CTI-SVM Proactive Defense: Detected {$atkType} from {$srcIp} on port {$port} (Sensor: {$sensor}, SVM Confidence: {$conf}%)</description>";
            $xmlLines[] = "    <mitre>";
            $xmlLines[] = "      <id>T1110</id>";
            $xmlLines[] = "    </mitre>";
            $xmlLines[] = "    <group>cti_threat_detected,pci_dss_11.4,gdpr_IV_35.7.d,</group>";
            $xmlLines[] = "  </rule>";
            $ruleId++;
        }

        $xmlLines[] = '</group>';
        $xmlContent = implode("\n", $xmlLines);

        return [
            'filename' => 'wazuh_cti_svm_rules_' . date('Ymd_His') . '.xml',
            'rule_count' => count($seenIps),
            'xml_content' => $xmlContent,
        ];
    }

    /**
     * Generates MISP Event & Attributes JSON Feed (matching Figure 3.3 on page 57 of thesis.pdf)
     * from SVM-detected Cyber Threats (predicted_label = 1).
     */
    public function exportMispFeed(): array
    {
        $pdo = Database::connection();
        $threats = $pdo->query("
            SELECT * FROM honeypot_predictions
            WHERE predicted_label = 1
            ORDER BY id DESC
            LIMIT 100
        ")->fetchAll();

        if (empty($threats)) {
            $threats = $pdo->query("
                SELECT * FROM threats
                WHERE label IN ('1', '+1', 'threat', 'Threat')
                ORDER BY id DESC
                LIMIT 25
            ")->fetchAll();
        }

        $attributes = [];
        foreach ($threats as $idx => $t) {
            $srcIp = (string) ($t['source_ip'] ?? '68.183.55.117');
            $port = (string) ($t['port'] ?? '22');
            $domain = (string) ($t['domain_name'] ?? 'circl.lu');
            $ts = (string) ($t['timestamp'] ?? date('Y-m-d\TH:i:s\Z'));
            $atkType = (string) ($t['attack_type'] ?? 'SSH Brute Force');

            $attributes[] = [
                'uuid' => self::uuidFromSeed("ip-{$srcIp}-{$idx}"),
                'type' => 'ip-dst',
                'object_relation' => 'ip',
                'value' => $srcIp,
                'comment' => "SVM Predicted Cyber Threat (+1): {$atkType}",
                'to_ids' => true,
            ];
            $attributes[] = [
                'uuid' => self::uuidFromSeed("port-{$port}-{$idx}"),
                'type' => 'port',
                'object_relation' => 'dst-port',
                'value' => $port,
                'to_ids' => false,
            ];
            $attributes[] = [
                'uuid' => self::uuidFromSeed("domain-{$domain}-{$idx}"),
                'type' => 'domain',
                'object_relation' => 'domain',
                'value' => $domain,
                'to_ids' => true,
            ];
            $attributes[] = [
                'uuid' => self::uuidFromSeed("dt-{$ts}-{$idx}"),
                'type' => 'datetime',
                'object_relation' => 'first-seen',
                'value' => str_replace(' ', 'T', $ts) . 'Z',
                'to_ids' => false,
            ];
        }

        $mispFeed = [
            'Event' => [
                'name' => 'ip-port',
                'meta-category' => 'network',
                'description' => 'Proactive CTI-SVM Defense Automated Threat Intelligence Feed (An IP address or domain and a port)',
                'info' => 'SVM Classifier Detected Honeypot Cyber Threats',
                'uuid' => self::uuidFromSeed('misp-event-' . date('YmdHis')),
                'timestamp' => (string) time(),
                'threat_level_id' => '1',
                'analysis' => '2',
                'Attribute' => $attributes,
            ],
        ];

        return [
            'filename' => 'misp_cti_svm_feed_' . date('Ymd_His') . '.json',
            'threat_count' => count($threats),
            'attribute_count' => count($attributes),
            'json_content' => json_encode($mispFeed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'feed' => $mispFeed,
        ];
    }

    private static function uuidFromSeed(string $seed): string
    {
        $h = md5($seed);
        return sprintf(
            '%s-%s-4%s-a%s-%s',
            substr($h, 0, 8),
            substr($h, 8, 4),
            substr($h, 13, 3),
            substr($h, 17, 3),
            substr($h, 20, 12)
        );
    }
}
