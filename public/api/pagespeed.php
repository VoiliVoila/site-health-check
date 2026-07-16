<?php
/**
 * POST /api/pagespeed.php  { url }
 *
 * The Performance pillar: 4 items, in a causal chain.
 *   mobile score  → the verdict
 *   LCP           → what the visitor feels
 *   page weight   → the cause
 *   images        → the quantified lever
 *
 * The Google call takes 10 to 30 s. The front end fires it alongside the first
 * scan: by the time the visitor has read those results, this one is ready.
 */

declare(strict_types=1);

require_once __DIR__ . '/checks.php';
require_once __DIR__ . '/ratelimit.php';

// See scan.php: cross-origin header only when explicitly configured.
if ($allowOrigin = getenv('CHECK_ALLOW_ORIGIN')) {
    header('Access-Control-Allow-Origin: ' . $allowOrigin);
    header('Vary: Origin');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('Méthode non autorisée.', 405);
}

rate_limit_or_fail();

$config = require __DIR__ . '/../../config.php';

$input = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
$url   = normalize_url((string) ($input['url'] ?? ''));
assert_public_host($url);

set_time_limit(90);

$ind = pillar_performance($url, $config);

if ($ind === null) {
    json_out([
        'indisponible' => true,
        'message'      => "Google n'a pas pu analyser ce site pour le moment. Les autres résultats restent valables.",
    ]);
}

json_out([
    'piliers' => [[
        'id'          => 'performance',
        'titre'       => 'Performance',
        'question'    => 'Vos visiteurs attendent-ils ?',
        'score'       => pillar_score($ind),
        'indicateurs' => $ind,
    ]],
]);
