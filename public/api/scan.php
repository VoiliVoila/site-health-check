<?php
/**
 * POST /api/scan.php  { url, groupe: "visibilite" | "securite" | "entretien" }
 *
 * One request = one pillar, so the front end can display them in the chosen
 * order (Visibility first — fast and concrete — while Security runs its probes,
 * then Maintenance). Broken-link checks are the slow part.
 */

declare(strict_types=1);

require_once __DIR__ . '/checks.php';
require_once __DIR__ . '/ratelimit.php';

// Cross-origin header only when explicitly configured. Left unset, the tool is
// same-origin only (the front end and the API share one domain) — the safe default.
if ($allowOrigin = getenv('CHECK_ALLOW_ORIGIN')) {
    header('Access-Control-Allow-Origin: ' . $allowOrigin);
    header('Vary: Origin');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('Méthode non autorisée.', 405);
}

rate_limit_or_fail();

$input  = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
$groupe = $input['groupe'] ?? 'visibilite';
if (!in_array($groupe, ['visibilite', 'securite', 'entretien'], true)) {
    fail('Groupe inconnu.');
}

$url = normalize_url((string) ($input['url'] ?? ''));
assert_public_host($url);

set_time_limit(60);

$home = http_fetch($url, ['follow' => true, 'max' => 900_000]);

if ($home['error'] || $home['status'] === 0) {
    fail("Impossible de joindre ce site. Il est peut-être hors ligne, ou protégé contre les outils d'analyse.", 422);
}
if ($home['status'] >= 400) {
    fail("Ce site répond par une erreur {$home['status']}. Vérifiez l'adresse.", 422);
}

$finalUrl = $home['url'];
$origin   = origin_of($finalUrl);
$isWp     = is_wordpress($home['body'], $home['headers']);

// One group = one pillar. The front end calls them in the intended order
// (Visibility first, free and concrete, while Security runs its probes).
$piliers = [
    'visibilite' => [
        'titre'    => 'Visibilité',
        'question' => 'Google et vos clients vous trouvent-ils ?',
        'calcul'   => fn() => pillar_visibilite($home, $origin),
    ],
    'securite' => [
        'titre'    => 'Sécurité',
        'question' => 'Votre site est-il une porte ouverte ?',
        'calcul'   => fn() => pillar_securite($home, $origin, $isWp),
    ],
    'entretien' => [
        'titre'    => 'Entretien',
        'question' => "Est-ce que quelqu'un s'en occupe ?",
        'calcul'   => fn() => pillar_entretien($home, $origin, $isWp),
    ],
];

$p           = $piliers[$groupe];
$indicateurs = ($p['calcul'])();

json_out([
    'url'       => $finalUrl,
    'wordpress' => $isWp,
    'piliers'   => [[
        'id'          => $groupe,
        'titre'       => $p['titre'],
        'question'    => $p['question'],
        'score'       => pillar_score($indicateurs),
        'indicateurs' => $indicateurs,
    ]],
]);
