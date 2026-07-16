<?php
/**
 * Expert report on the command line — JSON to stdout.
 *
 *   docker run --rm -v "$PWD":/app -w /app php:8.3-cli \
 *     php audit-cli.php https://exemple.fr --perf
 *
 * Same engine as the public audit (checks.php), full expert output with the
 * raw technical facts. Private use only (see report.php).
 */

declare(strict_types=1);

require_once __DIR__ . '/public/api/report.php';

$args   = array_slice($argv, 1);
$url    = null;
$perf   = false;
foreach ($args as $a) {
    if ($a === '--perf') {
        $perf = true;
    } elseif ($url === null) {
        $url = $a;
    }
}

if ($url === null) {
    fwrite(STDERR, "Usage: php audit-cli.php <url> [--perf]\n");
    exit(1);
}

$configPath = __DIR__ . '/config.php';
$config     = is_file($configPath) ? require $configPath : ['pagespeed_key' => ''];

echo json_encode(
    full_report($url, $perf, $config),
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
), "\n";
