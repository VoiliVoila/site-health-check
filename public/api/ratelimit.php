<?php
/**
 * Simple per-IP, file-based rate limit — the tool is public and makes outbound
 * requests: without this it would become a scan relay for anyone.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib.php';

const RL_FENETRE = 3600; // 1 h
const RL_MAX     = 20;   // scans per IP per hour

function rate_limit_or_fail(): void
{
    $dir = __DIR__ . '/../../data/ratelimit';
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        return; // no storage: do not block the service from running
    }

    $ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $file = $dir . '/' . hash('sha256', $ip) . '.json';
    $now  = time();

    $hits = [];
    if (is_file($file)) {
        $hits = json_decode((string) @file_get_contents($file), true) ?: [];
    }
    $hits = array_values(array_filter($hits, fn($t) => $now - $t < RL_FENETRE));

    if (count($hits) >= RL_MAX) {
        fail('Trop de tests lancés depuis cette connexion. Réessayez dans une heure.', 429);
    }

    $hits[] = $now;
    @file_put_contents($file, json_encode($hits), LOCK_EX);
}
