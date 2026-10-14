<?php

use App\Http\Controllers\CtiSourceController;
use App\Http\Controllers\DatasetController;
use App\Http\Controllers\ExportController;
use App\Http\Controllers\SvmController;

return [
    'GET /api/health' => fn() => ['status' => 'ok', 'service' => 'laravel-cti-backend'],

    // Menu 1: Overview & CTI Data Sources (MISP, Wazuh, Honeypot)
    'GET /api/overview' => fn() => (new DatasetController())->overview(),
    'GET /api/sources' => fn() => (new CtiSourceController())->index(),
    'POST /api/sources/config' => fn(array $body) => (new CtiSourceController())->updateConfig($body),
    'POST /api/sources/pull' => fn(array $body) => (new CtiSourceController())->pullFromSource($body),
    'POST /api/sources/upload' => fn(array $body) => (new CtiSourceController())->uploadLogs($body),

    // Menu 2: Dataset & Preprocessing Pipeline (Chapter 4.4 - 4.5)
    'GET /api/dataset' => fn(array $body, array $query) => (new DatasetController())->listDataset($query),
    'POST /api/dataset/seed' => fn(array $body) => (new DatasetController())->seedDataset($body),
    'POST /api/dataset/preprocess' => fn(array $body) => (new DatasetController())->runPreprocessing($body),

    // Menu 3: SVM Model Training & Evaluation (Chapter 4.6 - 4.7 & 4.10)
    'GET /api/svm/history' => fn() => (new SvmController())->history(),
    'POST /api/svm/train' => fn(array $body) => (new SvmController())->train($body),

    // Menu 4: Prediction of Unseen Data (Honeypot) & Export Rules (Chapter 3.3 & 4.8)
    'GET /api/svm/predictions' => fn() => (new SvmController())->listPredictions(),
    'POST /api/svm/predict' => fn(array $body) => (new SvmController())->predict($body),
    'POST /api/svm/predict-honeypot-batch' => fn(array $body) => (new SvmController())->predictHoneypotBatch($body),
    'GET /api/export/wazuh-rules' => fn() => (new ExportController())->exportWazuhRules(),
    'GET /api/export/misp-feed' => fn() => (new ExportController())->exportMispFeed(),
];
