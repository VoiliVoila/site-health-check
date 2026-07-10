<?php
/**
 * Shared foundation: URL normalisation, SSRF guard, HTTP client, parsing.
 */

declare(strict_types=1);

const UA = 'SiteHealthCheck/1.0';
const TIMEOUT = 8;

function json_out(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(string $message, int $status = 400): void
{
    json_out(['error' => $message], $status);
}

/**
 * Accepts "example.com", "www.example.com/contact", "https://example.com".
 * Returns an absolute https URL, without fragment.
 */
function normalize_url(string $raw): string
{
    $raw = trim($raw);
    if ($raw === '') {
        fail('Adresse vide.');
    }
    if (!preg_match('~^https?://~i', $raw)) {
        $raw = 'https://' . $raw;
    }
    $parts = parse_url($raw);
    if ($parts === false || empty($parts['host'])) {
        fail('Adresse invalide.');
    }
    $host = strtolower($parts['host']);
    if (!preg_match('~^[a-z0-9.-]+\.[a-z]{2,}$~', $host)) {
        fail('Nom de domaine invalide.');
    }
    $scheme = strtolower($parts['scheme'] ?? 'https');
    $path   = $parts['path'] ?? '/';
    $query  = isset($parts['query']) ? '?' . $parts['query'] : '';

    return $scheme . '://' . $host . $path . $query;
}

/**
 * SSRF guard: reject anything that does not resolve to a public IP.
 * Without it, anyone could scan the host's internal network by submitting
 * http://127.0.0.1/ or http://169.254.169.254/ (cloud metadata endpoint).
 */
function assert_public_host(string $url): void
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) {
        fail('Adresse invalide.');
    }

    $ips = [];
    foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA] as $key => $type) {
        $records = @dns_get_record($host, $type) ?: [];
        foreach ($records as $r) {
            if (!empty($r['ip']))   { $ips[] = $r['ip']; }
            if (!empty($r['ipv6'])) { $ips[] = $r['ipv6']; }
        }
    }
    if (!$ips) {
        fail("Ce nom de domaine ne répond pas. Vérifiez l'orthographe.", 422);
    }

    foreach ($ips as $ip) {
        $public = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if ($public === false) {
            fail('Adresse non autorisée.', 422);
        }
    }
}

/**
 * HTTP request. Follows redirects only when asked, and refuses to follow
 * towards a private IP (a redirect could otherwise bypass the guard).
 */
function http_fetch(string $url, array $opts = []): array
{
    $method     = $opts['method']   ?? 'GET';
    $follow     = $opts['follow']   ?? true;
    $maxBytes   = $opts['max']      ?? 900_000;
    $timeout    = $opts['timeout']  ?? TIMEOUT;

    $ch = curl_init();
    $headers = [];
    $body = '';

    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false, // handled manually to revalidate every hop
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_USERAGENT      => UA,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_ENCODING       => '',
        CURLOPT_NOBODY         => $method === 'HEAD',
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
            $p = explode(':', $line, 2);
            if (count($p) === 2) {
                $headers[strtolower(trim($p[0]))] = trim($p[1]);
            }
            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$body, $maxBytes) {
            $body .= $chunk;
            if (strlen($body) > $maxBytes) {
                return 0; // stop the transfer: we have read enough
            }
            return strlen($chunk);
        },
    ]);

    $ok        = curl_exec($ch);
    $errno     = curl_errno($ch);
    $status    = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $ttfb      = (float) curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME);
    $sslVerify = (int) curl_getinfo($ch, CURLINFO_SSL_VERIFYRESULT);
    curl_close($ch);

    // CURLE_WRITE_ERROR (23) = our deliberate cut-off, not a real error.
    $hardError = $errno !== 0 && $errno !== 23;

    $result = [
        'url'        => $url,
        'status'     => $status,
        'headers'    => $headers,
        'body'       => $body,
        'ttfb'       => $ttfb,
        'error'      => $hardError ? curl_strerror($errno) : null,
        'errno'      => $hardError ? $errno : 0,
        'ssl_verify' => $sslVerify,
    ];

    if ($follow && $status >= 300 && $status < 400 && !empty($headers['location'])) {
        $next = absolutize($headers['location'], $url);
        if ($next && ($opts['_depth'] ?? 0) < 5) {
            assert_public_host($next);
            $opts['_depth'] = ($opts['_depth'] ?? 0) + 1;
            $hop = http_fetch($next, $opts);
            $hop['redirected_from'] = $url;
            $hop['first_status']    = $result['first_status'] ?? $status;
            return $hop;
        }
    }

    return $result;
}

function absolutize(?string $href, string $base): ?string
{
    if (!$href) {
        return null;
    }
    $href = trim($href);
    if ($href === '' || str_starts_with($href, '#')) {
        return null;
    }
    if (preg_match('~^https?://~i', $href)) {
        return $href;
    }
    if (str_starts_with($href, '//')) {
        return (parse_url($base, PHP_URL_SCHEME) ?: 'https') . ':' . $href;
    }

    $scheme = parse_url($base, PHP_URL_SCHEME) ?: 'https';
    $host   = parse_url($base, PHP_URL_HOST);
    if (!$host) {
        return null;
    }
    $port = parse_url($base, PHP_URL_PORT);
    $root = $scheme . '://' . $host . ($port ? ':' . $port : '');

    if (str_starts_with($href, '/')) {
        return $root . $href;
    }
    if (preg_match('~^(mailto|tel|javascript|data):~i', $href)) {
        return null;
    }

    $dir = rtrim(dirname(parse_url($base, PHP_URL_PATH) ?: '/'), '/');
    return $root . $dir . '/' . $href;
}

function origin_of(string $url): string
{
    $scheme = parse_url($url, PHP_URL_SCHEME) ?: 'https';
    $host   = parse_url($url, PHP_URL_HOST);
    return $scheme . '://' . $host;
}

/**
 * Certificate: issuer, expiry date, days remaining.
 */
function ssl_info(string $url): ?array
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host || parse_url($url, PHP_URL_SCHEME) !== 'https') {
        return null;
    }

    $ctx = stream_context_create(['ssl' => [
        'capture_peer_cert' => true,
        'verify_peer'       => false, // read the cert even when it is invalid
        'verify_peer_name'  => false,
        'SNI_enabled'       => true,
        'peer_name'         => $host,
    ]]);

    $client = @stream_socket_client(
        "ssl://{$host}:443",
        $errno,
        $errstr,
        6,
        STREAM_CLIENT_CONNECT,
        $ctx
    );
    if (!$client) {
        return null;
    }

    $params = stream_context_get_params($client);
    fclose($client);

    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    if (!$cert) {
        return null;
    }
    $parsed = openssl_x509_parse($cert);
    if (!$parsed || empty($parsed['validTo_time_t'])) {
        return null;
    }

    $expiry = (int) $parsed['validTo_time_t'];
    return [
        'issuer'     => $parsed['issuer']['O'] ?? ($parsed['issuer']['CN'] ?? 'inconnu'),
        'expires_at' => date('c', $expiry),
        'days_left'  => (int) floor(($expiry - time()) / 86400),
    ];
}

/** DOMDocument tolerant of malformed HTML (i.e. the whole web). */
function dom_of(string $html): ?DOMXPath
{
    if (trim($html) === '') {
        return null;
    }
    $prev = libxml_use_internal_errors(true);
    $doc  = new DOMDocument();
    $doc->loadHTML('<?xml encoding="utf-8" ?>' . $html);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);

    return new DOMXPath($doc);
}

function meta_content(DOMXPath $xp, string $name, string $attr = 'name'): ?string
{
    $nodes = $xp->query("//meta[translate(@{$attr},'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='" . strtolower($name) . "']/@content");
    if ($nodes && $nodes->length) {
        $v = trim($nodes->item(0)->nodeValue);
        return $v === '' ? null : $v;
    }
    return null;
}
