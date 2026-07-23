<?php
/**
 * POST /api/lead.php  { email, url, consent, resultats?, score? }
 *
 * Unlocks the remaining pillars and records the contact.
 * GDPR: explicit consent required, email and URL only, timestamp kept as
 * proof of consent.
 *
 * Three outputs:
 *   1. leads.csv           — the contact line (as before)
 *   2. data/reports/       — full scan results as JSON (for follow-up)
 *   3. Internal email      — enriched with scores and key findings
 *   4. Visitor email       — short recap so they keep a trace
 */

declare(strict_types=1);

require_once __DIR__ . '/lib.php';
require_once __DIR__ . '/ratelimit.php';

if ($allowOrigin = getenv('CHECK_ALLOW_ORIGIN')) {
    header('Access-Control-Allow-Origin: ' . $allowOrigin);
    header('Vary: Origin');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('Méthode non autorisée.', 405);
}

rate_limit_or_fail();

$config = require __DIR__ . '/../../config.php';

$input     = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
$email     = trim((string) ($input['email'] ?? ''));
$url       = trim((string) ($input['url'] ?? ''));
$consent   = (bool) ($input['consent'] ?? false);
$resultats = $input['resultats'] ?? [];
$score     = isset($input['score']) ? (int) $input['score'] : null;

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fail('Adresse e-mail invalide.', 422);
}
if (!$consent) {
    fail('Le consentement est nécessaire pour recevoir le rapport.', 422);
}

/* ---- 1. leads.csv ---- */

$dir = __DIR__ . '/../../data';
if (!is_dir($dir)) {
    @mkdir($dir, 0755, true);
}

$ligne = [date('c'), $email, $url, 'consentement-explicite'];
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

/* ---- 2. Store report JSON ---- */

if (!empty($resultats)) {
    $reportDir = $dir . '/reports';
    if (!is_dir($reportDir)) {
        @mkdir($reportDir, 0755, true);
    }
    $host = parse_url($url, PHP_URL_HOST) ?: parse_url("https://{$url}", PHP_URL_HOST) ?: 'unknown';
    $slug = preg_replace('~[^a-z0-9.-]~', '_', strtolower($host));
    $reportFile = $reportDir . '/' . $slug . '_' . date('Y-m-d_His') . '.json';
    @file_put_contents($reportFile, json_encode([
        'date'      => date('c'),
        'email'     => $email,
        'url'       => $url,
        'score'     => $score,
        'piliers'   => $resultats,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
}

/* ---- 3. Internal notification (enriched) ---- */

if (!empty($config['notify_to'])) {
    $body = build_internal_email($url, $email, $score, $resultats);
    $subject = utf8_subject('Check santé — ' . ($score !== null ? "{$score}/100" : 'nouveau test') . ' : ' . $url);
    send_application_email($config, $config['notify_to'], $subject, $body);
}

/* ---- 4. Visitor recap email ---- */

if (!empty($config['notify_from'])) {
    $visitorBody = build_visitor_email($url, $score, $resultats);
    send_application_email(
        $config,
        $email,
        utf8_subject("Votre bilan de santé : {$url}"),
        $visitorBody,
        $config['notify_to'] ?? $config['notify_from']
    );
}

json_out(['ok' => true]);

function utf8_subject(string $s): string
{
    return '=?UTF-8?B?' . base64_encode($s) . '?=';
}

/** Send application mail through the configured SMTP relay. */
function send_application_email(array $config, string $to, string $subject, string $body, ?string $replyTo = null): bool
{
    $from = trim((string) ($config['notify_from'] ?? ''));
    $host = trim((string) ($config['smtp_host'] ?? 'mail.infomaniak.com'));
    $port = (int) ($config['smtp_port'] ?? 587);
    $user = trim((string) ($config['smtp_user'] ?? $from));
    $pass = (string) ($config['smtp_password'] ?? '');

    if ($from === '' || $user === '' || $pass === '') {
        error_log('Audit SMTP is not configured');
        return false;
    }

    $socket = @stream_socket_client(
        "tcp://{$host}:{$port}",
        $errno,
        $errstr,
        15,
        STREAM_CLIENT_CONNECT
    );
    if (!$socket) {
        error_log("Audit SMTP connection failed ({$errno}): {$errstr}");
        return false;
    }
    stream_set_timeout($socket, 15);

    try {
        smtp_expect($socket, 220);
        smtp_command($socket, 'EHLO audit.lajetee.fr', 250);
        smtp_command($socket, 'STARTTLS', 220);
        if (!@stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            throw new RuntimeException('TLS negotiation failed');
        }
        smtp_command($socket, 'EHLO audit.lajetee.fr', 250);
        smtp_command($socket, 'AUTH LOGIN', 334);
        smtp_command($socket, base64_encode($user), 334);
        smtp_command($socket, base64_encode($pass), 235);
        smtp_command($socket, "MAIL FROM:<{$from}>", 250);
        smtp_command($socket, "RCPT TO:<{$to}>", 250);
        smtp_command($socket, 'DATA', 354);

        $headers = [
            "From: La Jetée <{$from}>",
            "To: {$to}",
            "Subject: {$subject}",
            'Date: ' . date(DATE_RFC2822),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@audit.lajetee.fr>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];
        if ($replyTo !== null) {
            $headers[] = "Reply-To: {$replyTo}";
        }
        $message = implode("\r\n", $headers) . "\r\n\r\n" . $body;
        $message = str_replace(["\r\n", "\r"], "\n", $message);
        $message = preg_replace('/(?m)^\./', '..', $message);
        fwrite($socket, str_replace("\n", "\r\n", $message) . "\r\n.\r\n");
        smtp_expect($socket, 250);
        fwrite($socket, "QUIT\r\n");
        fclose($socket);
        return true;
    } catch (Throwable $e) {
        error_log('Audit SMTP send failed: ' . $e->getMessage());
        fclose($socket);
        return false;
    }
}

function smtp_command($socket, string $command, int $expected): void
{
    fwrite($socket, $command . "\r\n");
    smtp_expect($socket, $expected);
}

function smtp_expect($socket, int $expected): string
{
    $response = '';
    while (($line = fgets($socket, 515)) !== false) {
        $response .= $line;
        if (isset($line[3]) && $line[3] === ' ') {
            break;
        }
    }
    $code = (int) substr($response, 0, 3);
    if ($code !== $expected) {
        throw new RuntimeException("SMTP {$code}, expected {$expected}");
    }
    return $response;
}

/* ==================================================================
 * Email builders
 * ================================================================== */

function build_internal_email(string $url, string $email, ?int $score, array $piliers): string
{
    $lines = [];
    $lines[] = "Site testé : {$url}";
    $lines[] = "E-mail : {$email}";
    $lines[] = 'Date : ' . date('d/m/Y H:i');
    if ($score !== null) {
        $lines[] = '';
        $lines[] = "SCORE GLOBAL : {$score}/100";
    }
    if (!empty($piliers)) {
        $lines[] = '';
        $lines[] = '--- Détail par pilier ---';
        foreach ($piliers as $p) {
            $ps = $p['score'] !== null ? "{$p['score']}/100" : 'n/a';
            $lines[] = '';
            $lines[] = strtoupper($p['titre'] ?? $p['id']) . " : {$ps}";
            foreach (($p['indicateurs'] ?? []) as $ind) {
                $icon = match($ind['status']) {
                    'ok'   => '✓',
                    'warn' => '⚠',
                    'fail' => '✗',
                    default => '—',
                };
                $lines[] = "  {$icon} {$ind['label']} — {$ind['verdict']}";
            }
        }
    }
    return implode("\n", $lines);
}

function build_visitor_email(string $url, ?int $score, array $piliers): string
{
    $lines = [];
    $lines[] = "Bonjour,";
    $lines[] = '';
    $lines[] = "Merci d'avoir testé {$url} avec notre outil de bilan de santé.";
    $lines[] = '';

    if ($score !== null) {
        $lines[] = "Votre score global : {$score}/100";
        $lines[] = '';
    }

    if (!empty($piliers)) {
        foreach ($piliers as $p) {
            $ps = $p['score'] !== null ? "{$p['score']}/100" : '—';
            $lines[] = "  • {$p['titre']} : {$ps}";
        }
        $lines[] = '';
    }

    $lines[] = "Vous pouvez relancer le test à tout moment pour mesurer vos progrès :";
    $lines[] = "https://audit.lajetee.fr";
    $lines[] = '';
    $lines[] = "Les points marqués « se corrige en 10 minutes » sont à votre portée.";
    $lines[] = "Pour le reste, La Jetée peut s'en charger :";
    $lines[] = "  • un coup de main ponctuel : https://lajetee.fr/depannage-wordpress/";
    $lines[] = "  • une maintenance qui veille toute l'année : https://lajetee.fr/maintenance-site-wordpress/";
    $lines[] = '';
    $lines[] = "Si vous avez des questions sur votre bilan, répondez simplement à cet e-mail.";
    $lines[] = '';
    $lines[] = "À bientôt,";
    $lines[] = "Cécile — La Jetée";
    $lines[] = "https://lajetee.fr";

    return implode("\n", $lines);
}
