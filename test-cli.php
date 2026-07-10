<?php
/**
 * Test harness: runs the three HTTP pillars against a real URL.
 *   docker run --rm -v "$PWD":/app -w /app php:8.3-cli php test-cli.php https://example.com
 */

declare(strict_types=1);
require_once __DIR__ . '/public/api/checks.php';

$url = normalize_url($argv[1] ?? 'https://example.com');
assert_public_host($url);

$t0   = microtime(true);
$home = http_fetch($url, ['follow' => true, 'max' => 900_000]);
printf("-> %s (HTTP %d, %.2fs)\n", $home['url'], $home['status'], microtime(true) - $t0);

if ($home['status'] === 0 || $home['status'] >= 400) {
    exit("Site unreachable.\n");
}

$origin = origin_of($home['url']);
$isWp   = is_wordpress($home['body'], $home['headers']);
printf("WordPress: %s\n\n", $isWp ? 'yes' : 'no');

$piliers = [
    'SECURITY'     => fn() => pillar_securite($home, $origin, $isWp),
    'MAINTENANCE'  => fn() => pillar_entretien($home, $origin, $isWp),
    'VISIBILITY'   => fn() => pillar_visibilite($home, $origin),
];

$icone = ['ok' => '[ ok ]', 'warn' => '[warn]', 'fail' => '[FAIL]', 'na' => '[ -- ]'];

foreach ($piliers as $titre => $fn) {
    $t = microtime(true);
    $ind = $fn();
    printf("-- %s -- %d/100  (%.1fs)\n", $titre, pillar_score($ind) ?? -1, microtime(true) - $t);
    foreach ($ind as $i) {
        printf("  %s %-28s %s\n", $icone[$i['status']], $i['label'], wordwrap($i['verdict'], 90, "\n" . str_repeat(' ', 40)));
    }
    echo "\n";
}
printf("Total: %.1fs\n", microtime(true) - $t0);
