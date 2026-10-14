<?php

namespace App\Support;

class Env
{
    private static array $vars = [];
    private static bool $loaded = false;

    public static function load(string $envPath): void
    {
        if (self::$loaded || !file_exists($envPath)) {
            return;
        }
        $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode('=', $line, 2);
            if (count($parts) === 2) {
                $key = trim($parts[0]);
                $val = trim($parts[1]);
                $val = trim($val, "\"'");
                self::$vars[$key] = $val;
            }
        }
        self::$loaded = true;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        if (!self::$loaded) {
            self::load(dirname(__DIR__, 2) . '/.env');
        }
        if (array_key_exists($key, self::$vars)) {
            return self::$vars[$key];
        }
        $envVal = getenv($key);
        return $envVal !== false ? $envVal : $default;
    }
}
