<?php

namespace App\Services;

use App\Support\Env;
use RuntimeException;

class MlServiceClient
{
    private string $baseUrl;

    public function __construct()
    {
        $this->baseUrl = rtrim((string) Env::get('ML_SERVICE_URL', 'http://127.0.0.1:8001'), '/');
    }

    public function get(string $path, array $query = []): array
    {
        $url = $this->baseUrl . $path;
        if (!empty($query)) {
            $url .= '?' . http_build_query($query);
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $resp = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($resp === false) {
            throw new RuntimeException("Gagal menghubungi Python ML Service ({$url}): {$err}");
        }
        $decoded = json_decode((string) $resp, true);
        if ($httpCode >= 400) {
            $detail = is_array($decoded) ? ($decoded['detail'] ?? $resp) : $resp;
            throw new RuntimeException("Error dari Python ML Service (HTTP {$httpCode}): " . json_encode($detail));
        }
        return is_array($decoded) ? $decoded : [];
    }

    public function post(string $path, array $payload = []): array
    {
        $url = $this->baseUrl . $path;
        $jsonBody = json_encode($payload, JSON_UNESCAPED_SLASHES);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonBody,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/json',
            ],
        ]);
        $resp = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($resp === false) {
            throw new RuntimeException("Gagal menghubungi Python ML Service ({$url}): {$err}");
        }
        $decoded = json_decode((string) $resp, true);
        if ($httpCode >= 400) {
            $detail = is_array($decoded) ? ($decoded['detail'] ?? $resp) : $resp;
            throw new RuntimeException("Error dari Python ML Service (HTTP {$httpCode}): " . json_encode($detail));
        }
        return is_array($decoded) ? $decoded : [];
    }
}
