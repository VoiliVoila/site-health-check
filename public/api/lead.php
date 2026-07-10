<?php
/**
 * POST /api/lead.php  { email, url, consent }
 *
 * Unlocks the remaining pillars and records the contact.
 * GDPR: explicit consent required, email and URL only, timestamp kept as
 * proof of consent.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib.php';
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

$input   = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
$email   = trim((string) ($input['email'] ?? ''));
$url     = trim((string) ($input['url'] ?? ''));
$consent = (bool) ($input['consent'] ?? false);

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fail('Adresse e-mail invalide.', 422);
}
if (!$consent) {
    fail('Le consentement est nécessaire pour recevoir le rapport.', 422);
}

$dir = __DIR__ . '/../../data';
if (!is_dir($dir)) {
    @mkdir($dir, 0755, true);
}

$ligne = [
    date('c'),
    $email,
    $url,
    'consentement-explicite',
];

$fichier = $dir . '/leads.csv';
$nouveau = !is_file($fichier);
if ($fh = @fopen($fichier, 'a')) {
    if (flock($fh, LOCK_EX)) {
        if ($nouveau) {
            fputcsv($fh, ['date', 'email', 'site_teste', 'consentement']);
        }
        fputcsv($fh, $ligne);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
}

// Internal notification, without blocking the response if the mail fails.
if (!empty($config['notify_to'])) {
    @mail(
        $config['notify_to'],
        'Check santé — nouveau test : ' . $url,
        "Site testé : {$url}\nE-mail : {$email}\nDate : " . date('d/m/Y H:i'),
        "From: {$config['notify_from']}\r\nContent-Type: text/plain; charset=utf-8"
    );
}

json_out(['ok' => true]);
