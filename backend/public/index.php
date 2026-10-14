<?php

declare(strict_types=1);

// PSR-4 Autoloader for App\* namespace
spl_autoload_register(function (string $class): void {
    $prefix = 'App\\';
    $baseDir = dirname(__DIR__) . '/app/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

// CORS Headers for React.js Frontend
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, Accept');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

header('Content-Type: application/json; charset=utf-8');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$uri = rtrim($uri, '/') ?: '/';

$rawInput = file_get_contents('php://input');
$body = [];
if (is_string($rawInput) && trim($rawInput) !== '') {
    $decoded = json_decode($rawInput, true);
    if (is_array($decoded)) {
        $body = $decoded;
    }
}
$query = $_GET ?? [];

$routes = require dirname(__DIR__) . '/routes/api.php';
$routeKey = "{$method} {$uri}";

try {
    if (!isset($routes[$routeKey])) {
        http_response_code(404);
        echo json_encode([
            'error' => "Endpoint tidak ditemukan: {$routeKey}",
            'available_routes' => array_keys($routes),
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $handler = $routes[$routeKey];
    $response = $handler($body, $query);

    if (is_array($response) && isset($response['error'])) {
        http_response_code(400);
    }

    echo json_encode($response, JSON_UNESCAPED_SLASHES);
} catch (\Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'error' => $e->getMessage(),
        'file' => basename($e->getFile()) . ':' . $e->getLine(),
    ], JSON_UNESCAPED_SLASHES);
}
