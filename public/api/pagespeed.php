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

$query = http_build_query([
    'url'      => $url,
    'strategy' => 'mobile',
    'category' => 'performance',
    'key'      => $config['pagespeed_key'] ?? '',
]);

$api = http_fetch(
    'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?' . $query,
    ['follow' => true, 'timeout' => 75, 'max' => 6_000_000]
);

if ($api['status'] !== 200) {
    json_out([
        'indisponible' => true,
        'message'      => "Google n'a pas pu analyser ce site pour le moment. Les autres résultats restent valables.",
    ]);
}

$data   = json_decode($api['body'], true) ?: [];
$lh     = $data['lighthouseResult'] ?? [];
$audits = $lh['audits'] ?? [];

$score = $lh['categories']['performance']['score'] ?? null;
$score = $score === null ? null : (int) round($score * 100);

$lcpMs   = $audits['largest-contentful-paint']['numericValue'] ?? null;
$poids   = $audits['total-byte-weight']['numericValue'] ?? null;

/** Combined image savings: modern formats + compression + dimensions. */
$gainImages = 0;
foreach (['modern-image-formats', 'uses-optimized-images', 'uses-responsive-images'] as $a) {
    $gainImages += (int) ($audits[$a]['details']['overallSavingsBytes'] ?? 0);
}

$mo = fn(float $octets): string => number_format($octets / 1_048_576, 1, ',', ' ') . ' Mo';
$s  = fn(float $ms): string     => number_format($ms / 1000, 1, ',', ' ') . ' s';

$ind = [];

// --- 1. Mobile score ---
if ($score === null) {
    $ind[] = ind('score_mobile', 'Score mobile', 'na', "Google n'a pas pu calculer de score.");
} else {
    $st = $score >= 70 ? 'ok' : ($score >= 40 ? 'warn' : 'fail');
    $ind[] = ind('score_mobile', 'Score mobile', $st,
        $score >= 70
            ? "Google note la vitesse de votre site {$score} sur 100 sur mobile. C'est bon."
            : "Google note la vitesse de votre site {$score} sur 100 sur mobile. Plus de la moitié de vos visiteurs sont sur téléphone.",
        $score < 40 ? "En dessous de 40, le problème est structurel : c'est le socle du site qu'il faut reprendre, pas quelques réglages." : '',
        ['valeur' => $score]
    );
}

// --- 2. LCP ---
if ($lcpMs === null) {
    $ind[] = ind('lcp', "Vitesse d'affichage", 'na', 'Mesure indisponible.');
} else {
    $st = $lcpMs <= 2500 ? 'ok' : ($lcpMs <= 4000 ? 'warn' : 'fail');
    $ind[] = ind('lcp', "Vitesse d'affichage", $st,
        "Sur un téléphone, votre contenu principal apparaît au bout de " . $s((float) $lcpMs) . ".",
        $st === 'ok' ? '' : "Au-delà de 2,5 secondes, un visiteur sur quatre est déjà reparti.",
        ['valeur' => round($lcpMs / 1000, 1)]
    );
}

// --- 3. Page weight ---
if ($poids === null) {
    $ind[] = ind('poids', 'Poids de la page', 'na', 'Mesure indisponible.');
} else {
    $st = $poids <= 1_600_000 ? 'ok' : ($poids <= 3_500_000 ? 'warn' : 'fail');
    $ind[] = ind('poids', 'Poids de la page', $st,
        "Votre page d'accueil pèse " . $mo((float) $poids) . ". C'est ce que chaque visiteur télécharge, souvent en 4G.",
        $st === 'ok' ? '' : "Une page d'accueil bien tenue reste sous 1,5 Mo.",
        ['valeur' => round($poids / 1_048_576, 1)]
    );
}

// --- 4. Images to compress ---
if ($gainImages < 50_000) {
    $ind[] = ind('images', 'Images à alléger', 'ok',
        'Vos images sont correctement compressées. Rien à gagner de ce côté.');
} else {
    $st = $gainImages > 1_000_000 ? 'fail' : 'warn';
    $ind[] = ind('images', 'Images à alléger', $st,
        "Vos images peuvent être allégées de " . $mo((float) $gainImages) . " sans aucune perte visible.",
        "Compresser les photos et les servir au format WebP. C'est le gain le plus rapide à obtenir sur un site.",
        ['valeur' => round($gainImages / 1_048_576, 1)]
    );
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
