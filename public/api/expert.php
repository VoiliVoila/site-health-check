<?php
/**
 * GET|POST /api/expert.php  { url, perf?: 0|1 }
 *
 * PRIVATE expert report — the full analysis WITH the raw technical facts
 * (exposed usernames, forgotten files, WordPress version, security headers…),
 * for authenticated local tooling.
 *
 * GATED ON PURPOSE. This must never be reachable by the public:
 *   - allowed from the loopback interface (the local Docker engine), or
 *   - with a matching `expert_token` from config.php.
 * Any other caller gets 403. See report.php for why this data stays private.
 *
 * No rate limit and no lead gate here — it is a private, authenticated tool,
 * not the public lead magnet.
 */

declare(strict_types=1);

require_once __DIR__ . '/report.php';

$config = require __DIR__ . '/../../config.php';

/** Loopback caller (the local engine container) or a valid token. */
function expert_authorized(array $config): bool
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (in_array($remote, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true)) {
        return true;
    }
    $token = $config['expert_token'] ?? (getenv('EXPERT_TOKEN') ?: '');
    if ($token === '') {
        return false; // no token configured → refuse every non-loopback call
    }
    $given = $_GET['token'] ?? $_POST['token'] ?? '';
    return is_string($given) && hash_equals($token, $given);
}

if (!expert_authorized($config)) {
    fail('Accès refusé. Endpoint expert réservé au local (ou jeton requis).', 403);
}

$body = [];
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $body = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
}

$rawUrl = (string) ($_GET['url'] ?? $body['url'] ?? '');
if ($rawUrl === '') {
    fail('Paramètre "url" manquant.');
}
$withPerf = (bool) (int) ($_GET['perf'] ?? $body['perf'] ?? 0);

json_out(full_report($rawUrl, $withPerf, $config));
