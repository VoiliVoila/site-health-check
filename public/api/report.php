<?php
/**
 * Shared expert report builder.
 *
 * `full_report()` runs the SAME pillar functions as the public client tool
 * (checks.php) and returns the complete result — every indicator with its
 * factual `detail` kept, plus a normalised `fait` string (the raw technical
 * value), the per-pillar scores and the overall health score.
 *
 * This is the single source consumed by:
 *   - expert.php   (private, loopback/token-gated HTTP endpoint)
 *   - audit-cli.php (command line)
 *   - any authenticated local tooling (over local HTTP)
 *
 * The public client view (index.html + app.js) is untouched: it keeps calling
 * scan.php / pagespeed.php and shows only the plain-language verdicts. One
 * engine, two views — change a pillar once, both views follow.
 *
 * PRIVATE ON PURPOSE. The report lists exposed usernames, forgotten files and
 * the WordPress version of sites that are not ours — a roadmap for an attacker.
 * It must never be served publicly. expert.php enforces that.
 */

declare(strict_types=1);

require_once __DIR__ . '/checks.php';

/**
 * Turn an indicator's structured `detail`/`apercu`/`partage` into one short
 * factual string — the raw technical fact behind the client verdict.
 */
function derive_fait(array $i, string $url = ''): string
{
    $id = $i['id'] ?? '';
    $d  = $i['detail']  ?? null;
    $st = $i['status']  ?? 'na';

    switch ($id) {
        // --- Security ---
        case 'cadenas':
            if (is_array($d) && isset($d['days_left'])) {
                $exp = isset($d['expires_at']) ? substr((string) $d['expires_at'], 0, 10) : '?';
                return "certificat {$d['issuer']} · expire {$exp} ({$d['days_left']} j)";
            }
            // No readable certificate: tell "served over http" (what Google
            // sees too) apart from a broken/expired certificate.
            if ($st === 'fail' || $st === 'warn') {
                return str_starts_with($url, 'http://')
                    ? 'servi en http — pas de cadenas (c\'est ce que Google lit)'
                    : 'certificat invalide ou expiré';
            }
            return 'HTTPS';

        case 'identifiants':
            if (is_array($d) && !empty($d['comptes'])) {
                return 'comptes exposés : ' . implode(', ', $d['comptes']);
            }
            return $st === 'na' ? 'non-WordPress' : 'aucun compte exposé';

        case 'login':
            return $st === 'na' ? 'non-WordPress'
                 : ($st === 'warn' ? 'wp-login.php accessible' : 'connexion non exposée');

        case 'fichiers':
            if (is_array($d) && $d) {
                return 'trouvés : ' . implode(', ', array_column($d, 'path'));
            }
            return $st === 'na' ? 'soft-404 (non testable)' : 'aucun fichier oublié';

        case 'protections':
            $present = is_array($d) && isset($d['present']) ? $d['present'] : [];
            $tous    = ['hsts', 'nosniff', 'frame', 'referrer'];
            $manque  = array_values(array_diff($tous, $present));
            return $manque ? 'manquants : ' . implode(', ', $manque)
                           : 'les 4 en-têtes présents';

        // --- Maintenance ---
        case 'casses':
            if (is_array($d) && $d) {
                $codes = array_unique(array_column($d, 'status'));
                return count($d) . ' cassé(s) (HTTP ' . implode('/', $codes) . ')';
            }
            return $st === 'na' ? 'non testable' : 'aucun lien cassé';

        case 'scripts':
            if (is_array($d) && $d) {
                return implode(' · ', array_column($d, 'detail'));
            }
            return 'à jour';

        case 'maj':
            if (is_array($d) && $d) {
                $best = null;
                foreach ($d as $s) {
                    if ($best === null || ($s['year'] ?? 0) > ($best['year'] ?? 0)) {
                        $best = $s;
                    }
                }
                return ($best['source'] ?? 'signal') . ' : ' . ($best['year'] ?? '?');
            }
            return 'date indéterminable';

        case 'mixte':
            if (is_array($d) && $d) {
                return count($d) . ' ressource(s) en http://';
            }
            return $st === 'na' ? 'n/a' : 'pas de contenu mixte';

        // --- Visibility ---
        case 'indexable':
            if (is_array($d) && $d) {
                return implode(' ; ', $d);
            }
            return 'indexable';

        case 'snippet':
            $ap = $i['apercu'] ?? [];
            $tl = isset($ap['titre']) ? mb_strlen((string) $ap['titre']) : 0;
            $dl = isset($ap['description']) && $ap['description'] !== null
                ? mb_strlen((string) $ap['description']) : 0;
            return "titre {$tl} car. · description {$dl} car.";

        case 'fiche':
            if (is_array($d) && !empty($d['manque'])) {
                return 'manque : ' . implode(', ', $d['manque']);
            }
            return $st === 'fail' ? 'aucun schema LocalBusiness' : 'fiche complète';

        case 'partage':
            $pg  = $i['partage'] ?? [];
            $img = !empty($pg['image']) ? 'image OK' : 'pas d\'image OG';
            $ttl = !empty($pg['titre']) ? 'titre OK' : 'pas de titre OG';
            return "{$img} · {$ttl}";

        // --- Performance ---
        case 'score_mobile':
        case 'lcp':
        case 'poids':
        case 'images':
            return (string) ($i['fait'] ?? ($i['valeur'] ?? ''));
    }

    return (string) ($i['fait'] ?? '');
}

/** Attach a `fait` to every indicator of a pillar. */
function with_faits(array $indicateurs, string $url = ''): array
{
    foreach ($indicateurs as &$i) {
        $i['fait'] = derive_fait($i, $url);
    }
    return $indicateurs;
}

/**
 * Expert-only: which platform / CMS powers the site?
 *
 * Distinguishes a WordPress site from a proprietary builder (Wix, Jimdo,
 * Squarespace…). Best-effort, "to be confirmed" in spirit: the generator tag is
 * reliable when present, otherwise it falls back to asset/header signatures.
 */
function detect_platform(array $home): ?array
{
    $html = $home['body'];

    // 1. <meta name="generator"> tag — the cleanest signal.
    if (preg_match('~name=["\']generator["\']\s+content=["\']([^"\']+)~i', $html, $m)) {
        $g = $m[1];
        $map = [
            'WordPress' => 'WordPress', 'Wix.com' => 'Wix', 'Wix' => 'Wix',
            'Squarespace' => 'Squarespace', 'Jimdo' => 'Jimdo', 'Joomla' => 'Joomla',
            'Drupal' => 'Drupal', 'Webflow' => 'Webflow', 'Shopify' => 'Shopify',
            'Weebly' => 'Weebly', 'Ghost' => 'Ghost', 'PrestaShop' => 'PrestaShop',
            'TYPO3' => 'TYPO3', 'SPIP' => 'SPIP', 'Odoo' => 'Odoo',
            'HubSpot' => 'HubSpot', 'Duda' => 'Duda',
        ];
        foreach ($map as $needle => $label) {
            if (stripos($g, $needle) !== false) {
                return ['name' => $label, 'source' => 'generator'];
            }
        }
    }

    // 2. Characteristic HTTP headers.
    $hj = strtolower(json_encode($home['headers']));
    if (strpos($hj, 'x-wix') !== false)                     { return ['name' => 'Wix', 'source' => 'header']; }
    if (strpos($hj, 'x-shopid') !== false)                  { return ['name' => 'Shopify', 'source' => 'header']; }
    if (strpos($hj, 'x-drupal') !== false)                  { return ['name' => 'Drupal', 'source' => 'header']; }

    // 3. HTML signatures (generator is often stripped). Order: proprietary
    //    builders first, WordPress last.
    $sig = [
        'Wix'         => ['static.wixstatic.com', 'wixstatic', '_wixCssStates', 'wix.com/'],
        'Squarespace' => ['static1.squarespace.com', 'squarespace.com', 'sqs-block'],
        'Jimdo'       => ['jimdo.com', 'jimdostatic', 'u.jimcdn.com'],
        'Shopify'     => ['cdn.shopify.com', 'myshopify.com', 'Shopify.theme'],
        'Webflow'     => ['assets.website-files.com', 'assets-global.website-files.com', 'webflow.js'],
        'Weebly'      => ['weeblysite.com', 'editmysite.com', 'weebly.com'],
        'Joomla'      => ['/media/jui/', '/media/system/js/', 'com_content', 'option=com_'],
        'Drupal'      => ['/sites/default/files', 'Drupal.settings', '/core/misc/drupal'],
        'PrestaShop'  => ['/modules/ps_', 'prestashop', 'var prestashop'],
        'WordPress'   => ['/wp-content/', '/wp-includes/', 'wp-json'],
    ];
    foreach ($sig as $name => $needles) {
        foreach ($needles as $n) {
            if (stripos($html, $n) !== false) {
                return ['name' => $name, 'source' => 'signature'];
            }
        }
    }

    return null;
}

/**
 * Full expert report for one URL.
 *
 * @param bool $withPerf  run the (slow) PageSpeed pillar too.
 * @return array{url:string,wordpress:bool,wp_version:?array,score:?int,piliers:array,injoignable?:bool}
 */
function full_report(string $rawUrl, bool $withPerf, array $config): array
{
    $url = normalize_url($rawUrl);
    assert_public_host($url);

    set_time_limit($withPerf ? 120 : 60);

    $home = http_fetch($url, ['follow' => true, 'max' => 900_000]);

    if ($home['error'] || $home['status'] === 0 || $home['status'] >= 400) {
        return [
            'url'        => $home['url'] ?? $url,
            'injoignable' => true,
            'status'     => $home['status'] ?? 0,
            'message'    => "Site injoignable ou en erreur (HTTP {$home['status']}).",
        ];
    }

    $finalUrl = $home['url'];
    $origin   = origin_of($finalUrl);
    $isWp     = is_wordpress($home['body'], $home['headers']);

    $piliers = [
        [
            'id'          => 'visibilite',
            'titre'       => 'Visibilité',
            'indicateurs' => with_faits(pillar_visibilite($home, $origin), $finalUrl),
        ],
        [
            'id'          => 'securite',
            'titre'       => 'Sécurité',
            'indicateurs' => with_faits(pillar_securite($home, $origin, $isWp), $finalUrl),
        ],
        [
            'id'          => 'entretien',
            'titre'       => 'Entretien',
            'indicateurs' => with_faits(pillar_entretien($home, $origin, $isWp), $finalUrl),
        ],
    ];

    if ($withPerf) {
        $perf = pillar_performance($finalUrl, $config);
        if ($perf !== null) {
            $piliers[] = [
                'id'          => 'performance',
                'titre'       => 'Performance',
                'indicateurs' => with_faits($perf, $finalUrl),
            ];
        }
    }

    // Per-pillar + overall health score (same weighting as the client tool).
    $scores = [];
    foreach ($piliers as &$p) {
        $p['score'] = pillar_score($p['indicateurs']);
        if ($p['score'] !== null) {
            $scores[] = $p['score'];
        }
    }
    unset($p);
    $overall = $scores ? (int) round(array_sum($scores) / count($scores)) : null;

    return [
        'url'        => $finalUrl,
        'status'     => $home['status'],
        'wordpress'  => $isWp,
        'plateforme' => detect_platform($home),
        'wp_version' => $isWp ? wp_version_sniff($home, $origin) : null,
        'ttfb_ms'    => isset($home['ttfb']) ? (int) round($home['ttfb'] * 1000) : null,
        'score'      => $overall,
        'piliers'    => $piliers,
    ];
}
