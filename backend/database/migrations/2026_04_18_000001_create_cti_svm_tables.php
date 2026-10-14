<?php

use App\Support\Database;

/**
 * Laravel Database Migration for CTI Proactive SVM Defense Tables:
 * - threats (Table 4.1 & Table 4.16 of thesis.pdf)
 * - svm_training_runs (Section 4.7 & 4.10)
 * - honeypot_predictions (Section 3.3 & 4.8)
 * - cti_source_configs (MISP, Wazuh, Honeypot connectors)
 */
return new class {
    public function up(): void
    {
        Database::connection();
    }
};
