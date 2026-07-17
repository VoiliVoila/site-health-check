<?php
/**
 * The 17 indicators (4 per pillar, 5 for Security).
 *
 * Three rules, no exception:
 *   1. An indicator is included only if it is always measurable from the
 *      outside. What cannot be measured returns `na`, never `fail`.
 *   2. Its consequence fits in one sentence, understandable without any
 *      technical background.
 *   3. It points to an action — whether the owner does it themselves or not.
 *
 * `na` = not applicable (non-WordPress site) or indeterminable.
 * An `na` is removed from the pillar score; it does not penalise it.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib.php';

/**
 * Correction level per finding — powers the "se corrige en 10 minutes" badge
 * (the blog article promises the report tells the reader which ones).
 * facile    = the owner can do it alone, ~10 minutes, no technical skill
 * technique = needs hosting/code/plugin work — hand it over
 */
const NIVEAU_CORRECTION = [
    'indexable'    => 'facile',     // décocher une case dans WordPress
    'snippet'      => 'facile',     // écrire titre + description
    'partage'      => 'facile',     // choisir une image de partage
    'casses'       => 'facile',     // corriger ou retirer le lien
    'maj'          => 'facile',     // publier une mise à jour / corriger l'année
    'images'       => 'facile',     // compresser les photos
    'cadenas'      => 'technique',
    'identifiants' => 'technique',
    'login'        => 'technique',
    'fichiers'     => 'technique',
    'protections'  => 'technique',
    'scripts'      => 'technique',
    'mixte'        => 'technique',
    'fiche'        => 'technique',
    'score_mobile' => 'technique',
    'lcp'          => 'technique',
    'poids'        => 'technique',
];

function ind(string $id, string $label, string $status, string $verdict, string $action = '', array $extra = []): array
{
    $base = [
        'id'      => $id,
        'label'   => $label,
        'status'  => $status,   // ok | warn | fail | na
        'verdict' => $verdict,
        'action'  => $action,
    ];
    if (($status === 'warn' || $status === 'fail') && isset(NIVEAU_CORRECTION[$id])) {
        $base['niveau'] = NIVEAU_CORRECTION[$id];
    }
    return array_merge($base, $extra);
}

/** Is the site running WordPress? Gates 3 indicators. */
function is_wordpress(string $html, array $headers): bool
{
    foreach (['/wp-content/', '/wp-includes/', 'wp-json', 'content="WordPress'] as $sig) {
        if (stripos($html, $sig) !== false) {
            return true;
        }
    }
    return isset($headers['link']) && stripos($headers['link'], 'wp-json') !== false;
}

/** A 200 on a URL that should not exist? That is a "soft 404". */
function soft_404_baseline(string $origin): bool
{
    $probe = http_fetch($origin . '/site-health-probe-' . bin2hex(random_bytes(6)), ['follow' => true, 'max' => 4000]);
    return $probe['status'] === 200;
}

/* ===========================================================
   PILLAR 1 — SECURITY
   =========================================================== */

function pillar_securite(array $home, string $origin, bool $isWp): array
{
    $out = [];

    // --- 1. Valid padlock ---
    $ssl   = ssl_info($home['url']);
    $https = str_starts_with($home['url'], 'https://');

    if (!$https || $home['ssl_verify'] !== 0) {
        $out[] = ind('cadenas', 'Cadenas valide', 'fail',
            "Votre site n'a pas de cadenas valide. Les navigateurs affichent « Site non sécurisé » à vos visiteurs, et Google vous déclasse.",
            "Faire installer un certificat SSL — c'est gratuit et inclus chez tous les hébergeurs sérieux."
        );
    } elseif ($ssl && $ssl['days_left'] < 15) {
        $out[] = ind('cadenas', 'Cadenas valide', 'warn',
            "Votre certificat expire dans {$ssl['days_left']} jours. Passé cette date, vos visiteurs verront un écran d'avertissement rouge.",
            "Vérifier que le renouvellement automatique est bien actif chez votre hébergeur.",
            ['detail' => $ssl]
        );
    } else {
        $out[] = ind('cadenas', 'Cadenas valide', 'ok',
            'Votre site est bien servi en HTTPS, avec un certificat valide.', '',
            ['detail' => $ssl]
        );
    }

    // --- 2. Exposed usernames (WordPress) ---
    if (!$isWp) {
        $out[] = ind('identifiants', 'Identifiants visibles', 'na',
            "Cet indicateur ne concerne que les sites WordPress.");
    } else {
        $names = [];

        $api = http_fetch($origin . '/wp-json/wp/v2/users', ['follow' => true, 'max' => 60_000]);
        if ($api['status'] === 200) {
            $json = json_decode($api['body'], true);
            if (is_array($json)) {
                foreach ($json as $u) {
                    if (!empty($u['slug'])) {
                        $names[] = $u['slug'];
                    }
                }
            }
        }

        if (!$names) {
            $auth = http_fetch($origin . '/?author=1', ['follow' => false, 'max' => 4000]);
            if (in_array($auth['status'], [301, 302], true) && !empty($auth['headers']['location'])
                && preg_match('~/author/([^/?]+)~', $auth['headers']['location'], $m)) {
                $names[] = urldecode($m[1]);
            }
        }

        if ($names) {
            $names = array_slice(array_unique($names), 0, 5);
            $shown = implode(', ', array_map(fn($n) => '« ' . $n . ' »', $names));
            $out[] = ind('identifiants', 'Identifiants visibles', 'fail',
                "N'importe qui peut lire la liste de vos identifiants de connexion : {$shown}. Il ne reste plus qu'à deviner le mot de passe.",
                "Masquer la liste des auteurs — un plugin de sécurité le fait en une case à cocher.",
                ['detail' => ['comptes' => $names]]
            );
        } else {
            $out[] = ind('identifiants', 'Identifiants visibles', 'ok',
                'Vos identifiants de connexion ne sont pas exposés publiquement.');
        }
    }

    // --- 3. Exposed login page (WordPress) ---
    if (!$isWp) {
        $out[] = ind('login', 'Page de connexion', 'na',
            "Cet indicateur ne concerne que les sites WordPress.");
    } else {
        $login   = http_fetch($origin . '/wp-login.php', ['follow' => true, 'max' => 40_000]);
        $isForm  = $login['status'] === 200 && stripos($login['body'], 'user_login') !== false;

        if ($isForm) {
            $out[] = ind('login', 'Page de connexion', 'warn',
                "Votre page de connexion est à l'adresse que tout le monde connaît. Les robots la testent en continu, des milliers de fois par mois.",
                "Ajouter une double authentification, ou limiter les tentatives de connexion. Déplacer l'adresse aide un peu, mais ne suffit pas."
            );
        } else {
            $out[] = ind('login', 'Page de connexion', 'ok',
                "Votre page de connexion n'est pas accessible à l'adresse habituelle.");
        }
    }

    // --- 4. Forgotten files left accessible ---
    $soft = soft_404_baseline($origin);
    $cibles = [
        '/wp-content/debug.log' => ['journal de débogage', 'PHP'],
        '/.env'                 => ['fichier de configuration', '='],
        '/.git/config'          => ['dépôt de code source', '[core]'],
        '/backup.zip'           => ['archive de sauvegarde', 'PK'],
        '/wp-config.php.bak'    => ['configuration de la base de données', 'DB_PASSWORD'],
    ];

    $trouves = [];
    if (!$soft) {
        foreach ($cibles as $path => [$quoi, $signature]) {
            $r = http_fetch($origin . $path, ['follow' => false, 'max' => 3000]);
            if ($r['status'] === 200 && $r['body'] !== '' && stripos($r['body'], $signature) !== false) {
                $trouves[] = ['path' => $path, 'quoi' => $quoi];
            }
        }
    }

    if ($soft) {
        $out[] = ind('fichiers', 'Fichiers oubliés', 'na',
            "Votre site répond « page trouvée » à toutes les adresses, même inexistantes. Impossible de tester ce point de façon fiable.");
    } elseif ($trouves) {
        $liste = implode(', ', array_column($trouves, 'quoi'));
        $out[] = ind('fichiers', 'Fichiers oubliés', 'fail',
            "Des fichiers de travail traînent en accès libre sur votre site ({$liste}). Ils peuvent contenir vos mots de passe.",
            "Les supprimer du serveur aujourd'hui, puis changer les mots de passe qu'ils contenaient.",
            ['detail' => $trouves]
        );
    } else {
        $out[] = ind('fichiers', 'Fichiers oubliés', 'ok',
            'Aucun fichier de travail ou de sauvegarde accessible publiquement.');
    }

    // --- 5. Modern browser protections (security headers) ---
    // Framed as craftsmanship, not threat: these are free protections a
    // well-kept site switches on, and that an unmaintained one forgets.
    // Read straight from the home response headers — no extra request.
    $h = $home['headers'];
    $present = [];
    if (!empty($h['strict-transport-security'])) { $present[] = 'hsts'; }
    if (!empty($h['x-content-type-options']))    { $present[] = 'nosniff'; }
    if (!empty($h['x-frame-options'])
        || (!empty($h['content-security-policy']) && stripos($h['content-security-policy'], 'frame-ancestors') !== false)) {
        $present[] = 'frame';
    }
    if (!empty($h['referrer-policy']))           { $present[] = 'referrer'; }
    $nProt = count($present);

    if ($nProt >= 4) {
        $out[] = ind('protections', 'Sécurité navigation', 'ok',
            "Toutes les protections que les navigateurs offrent gratuitement sont activées. C'est le réglage des sites bien tenus.",
            '', ['detail' => ['present' => $present]]
        );
    } elseif ($nProt >= 2) {
        $out[] = ind('protections', 'Sécurité navigation', 'warn',
            "Une partie des protections navigateur sont en place, mais il en manque. Ce n'est pas une faille — c'est un réglage rapide que les sites soignés complètent.",
            "Ajouter les en-têtes de sécurité manquants — quelques lignes côté serveur, ou une case à activer dans Cloudflare.",
            ['detail' => ['present' => $present]]
        );
    } else {
        $out[] = ind('protections', 'Sécurité navigation', 'fail',
            "Votre site n'active pas les protections que les navigateurs offrent gratuitement (contre le détournement de votre site dans une autre page, ou le retour en connexion non sécurisée). Ce n'est pas une faille ouverte, mais c'est le genre de réglage qui manque quand personne ne s'occupe du site.",
            "Ajouter les en-têtes de sécurité — quelques lignes côté serveur, ou une case à activer dans Cloudflare.",
            ['detail' => ['present' => $present]]
        );
    }

    return $out;
}

/* ===========================================================
   PILLAR 2 — MAINTENANCE
   =========================================================== */

function pillar_entretien(array $home, string $origin, bool $isWp): array
{
    $out  = [];
    $html = $home['body'];
    $xp   = dom_of($html);

    // --- 1. Broken links and images ---
    $soft = soft_404_baseline($origin);
    if (!$xp || $soft) {
        $out[] = ind('casses', 'Liens et images', 'na',
            "Impossible de tester les liens de façon fiable sur ce site.");
    } else {
        // Cloudflare infra endpoints (email obfuscation, challenges…) are not
        // content links — skip them, or every Cloudflare site false-flags.
        $ignore = fn(string $u): bool => strpos($u, '/cdn-cgi/') !== false;

        $urls = [];
        $collect = function ($nodes, string $kind) use (&$urls, $home, $origin, $ignore) {
            foreach ($nodes ?: [] as $n) {
                $u = absolutize($n->nodeValue, $home['url']);
                if (!$u) {
                    continue;
                }
                // Drop the #fragment: it never affects the HTTP response, and
                // keeping it would count /page#a and /page#b as two links.
                $u = strtok($u, '#');
                if (str_starts_with($u, $origin) && !$ignore($u)) {
                    $urls[$u] ??= $kind;
                }
            }
        };
        $collect($xp->query('//a/@href'), 'lien');
        $collect($xp->query('//img/@src'), 'image');
        unset($urls[rtrim($home['url'], '/')], $urls[$origin], $urls[$origin . '/']);

        $urls    = array_slice($urls, 0, 15, true);
        $casses  = [];
        foreach ($urls as $u => $kind) {
            $r = http_fetch($u, ['method' => 'HEAD', 'follow' => true, 'timeout' => 5, 'max' => 1000]);
            if ($r['status'] >= 400 && $r['status'] !== 405 && $r['status'] !== 403) {
                $casses[] = ['url' => $u, 'type' => $kind, 'status' => $r['status']];
            }
        }

        $n = count($casses);
        $testes = count($urls);
        if ($n === 0) {
            $out[] = ind('casses', 'Liens et images', 'ok',
                "Les {$testes} liens et images testés depuis votre accueil fonctionnent tous.");
        } else {
            $imgs  = count(array_filter($casses, fn($c) => $c['type'] === 'image'));
            $liens = $n - $imgs;
            $quoi  = [];
            if ($liens) { $quoi[] = $liens . ' lien' . ($liens > 1 ? 's' : ''); }
            if ($imgs)  { $quoi[] = $imgs . ' image' . ($imgs > 1 ? 's' : ''); }
            $out[] = ind('casses', 'Liens et images', $n > 2 ? 'fail' : 'warn',
                implode(' et ', $quoi) . " de votre accueil ne mènent nulle part. Un visiteur qui clique tombe sur une page d'erreur.",
                "Corriger ou supprimer ces liens. C'est le premier signe qu'un site n'est plus suivi.",
                ['detail' => $casses]
            );
        }
    }

    // --- 3. Obsolete or admin scripts served to the public ---
    $problemes_scripts = [];

    // WordPress editor scripts (Gutenberg) served to visitors
    if ($isWp) {
        $editeur = ['block-editor.min.js', 'wp-block-editor', 'blocks.min.js', 'rich-text.min.js', 'components.min.js'];
        $vus = array_values(array_filter($editeur, fn($s) => stripos($html, $s) !== false));
        if (count($vus) >= 2) {
            $problemes_scripts[] = ['type' => 'admin', 'detail' => "l'éditeur WordPress (≈ 1 Mo de code inutile)"];
        }
    }

    // Outdated JS libraries (any site)
    if (preg_match('~jquery[./\-](\d+)\.(\d+)\.(\d+)~i', $html, $jq)) {
        $jqMajor = (int) $jq[1];
        $jqMinor = (int) $jq[2];
        if ($jqMajor < 3 || ($jqMajor === 3 && $jqMinor < 6)) {
            $jqVer = "{$jq[1]}.{$jq[2]}.{$jq[3]}";
            $problemes_scripts[] = ['type' => 'obsolete', 'detail' => "jQuery {$jqVer} (dernière version stable : 3.7)"];
        }
    }
    if (preg_match('~bootstrap[./\-](\d+)\.(\d+)~i', $html, $bs)) {
        if ((int) $bs[1] < 5) {
            $problemes_scripts[] = ['type' => 'obsolete', 'detail' => "Bootstrap {$bs[1]}.{$bs[2]} (version actuelle : 5.x)"];
        }
    }

    if ($problemes_scripts) {
        $liste = implode(' ; ', array_column($problemes_scripts, 'detail'));
        $hasAdmin = in_array('admin', array_column($problemes_scripts, 'type'));
        $hasObsolete = in_array('obsolete', array_column($problemes_scripts, 'type'));
        $label = 'Code à jour';
        $out[] = ind('scripts', $label, count($problemes_scripts) > 1 ? 'fail' : 'warn',
            "Votre site charge du code qui n'a rien à faire là : {$liste}. C'est du poids mort qui ralentit le site et signale un manque d'entretien.",
            "Mettre à jour les bibliothèques anciennes et réserver le code d'administration au back-office.",
            ['detail' => $problemes_scripts]
        );
    } else {
        $out[] = ind('scripts', 'Code à jour', 'ok',
            "Votre site ne charge pas de code obsolète ou d'administration inutile.");
    }

    // --- 4. Last update signal ---
    $courante = (int) date('Y');
    $signaux = [];

    // Try sitemap lastmod (handles both <urlset> and <sitemapindex>)
    $sitemapUrl = $origin . '/sitemap.xml';
    $sm = http_fetch($sitemapUrl, ['follow' => true, 'max' => 100_000, 'timeout' => 5]);
    if ($sm['status'] === 200 && (stripos($sm['body'], '<urlset') !== false || stripos($sm['body'], '<sitemapindex') !== false)) {
        if (preg_match_all('~<lastmod>(\d{4})-?(\d{2})?~', $sm['body'], $dates)) {
            $years = array_map('intval', $dates[1]);
            $maxYear = max($years);
            $signaux[] = ['source' => 'sitemap', 'year' => $maxYear];
        }
    }

    // Try RSS feed
    $rssDate = null;
    if ($xp) {
        $rssLink = null;
        foreach ($xp->query('//link[@type="application/rss+xml"]/@href') ?: [] as $n) {
            $rssLink = absolutize($n->nodeValue, $home['url']);
            break;
        }
        if ($rssLink) {
            $rss = http_fetch($rssLink, ['follow' => true, 'max' => 50_000, 'timeout' => 5]);
            if ($rss['status'] === 200) {
                if (preg_match_all('~<pubDate>([^<]+)</pubDate>~i', $rss['body'], $rdates)) {
                    $timestamps = array_filter(array_map('strtotime', $rdates[1]));
                    if ($timestamps) {
                        $latest = max($timestamps);
                        $rssYear = (int) date('Y', $latest);
                        $rssDate = ['year' => $rssYear, 'timestamp' => $latest];
                        $signaux[] = ['source' => 'rss', 'year' => $rssYear];
                    }
                }
            }
        }
    }

    // Fallback: footer year
    $footerYear = null;
    $pied = substr($html, -4000);
    if (preg_match_all('~(?:©|&copy;|copyright)\s*(?:-|–)?\s*((?:19|20)\d{2})~i', $pied, $m)) {
        $annees = array_map('intval', $m[1]);
        $footerYear = max($annees);
        $signaux[] = ['source' => 'footer', 'year' => $footerYear];
    }

    // Pick the best signal.
    // Sitemap lastmod = strong (reflects actual page updates).
    // Footer year     = moderate (someone touched the template).
    // RSS pubDate     = weak (only blog activity — many active sites don't blog).
    // RSS alone is never enough to conclude abandonment.
    $bestYear = null;
    $bestSource = null;
    $hasStrongSignal = false;
    foreach ($signaux as $s) {
        if ($bestYear === null || $s['year'] > $bestYear) {
            $bestYear = $s['year'];
            $bestSource = $s['source'];
        }
        if ($s['source'] !== 'rss') {
            $hasStrongSignal = true;
        }
    }

    if ($bestYear === null) {
        $out[] = ind('maj', 'Dernière mise à jour', 'na',
            "Impossible de déterminer la date de dernière mise à jour de ce site.");
    } elseif ($bestYear >= $courante - 1) {
        $out[] = ind('maj', 'Dernière mise à jour', 'ok',
            "Le site montre des signes d'activité récente.",
            '', ['detail' => $signaux]
        );
    } elseif (!$hasStrongSignal) {
        $out[] = ind('maj', 'Dernière mise à jour', 'na',
            "Le dernier article du blog date de {$bestYear}, mais cela ne veut pas dire que le site est abandonné — beaucoup de sites actifs ne publient pas d'articles.",
            '', ['detail' => $signaux]
        );
    } else {
        $ecart = $courante - $bestYear;
        $sourceTexte = match($bestSource) {
            'sitemap' => 'Le sitemap',
            'footer'  => 'Le pied de page',
            default   => 'Le site',
        };
        $out[] = ind('maj', 'Dernière mise à jour', $ecart >= 3 ? 'fail' : 'warn',
            "{$sourceTexte} indique {$bestYear} comme trace d'activité la plus récente. Un visiteur en déduit que le site est à l'abandon depuis {$ecart} ans.",
            "Publier du contenu régulièrement, même une actualité par trimestre, montre que quelqu'un s'occupe du site.",
            ['detail' => $signaux]
        );
    }

    // --- 5. Mixed content (http:// resources on an https page) ---
    $isHttps = str_starts_with($home['url'], 'https://');
    if (!$isHttps) {
        $out[] = ind('mixte', 'Contenu mixte', 'na',
            "Ce site n'est pas en HTTPS — le contenu mixte ne s'applique pas.");
    } elseif ($xp) {
        $mixtes = [];
        $checkMixed = function ($nodes, string $attr) use (&$mixtes, $origin) {
            foreach ($nodes ?: [] as $n) {
                $val = trim($n->nodeValue);
                if (str_starts_with($val, 'http://') && !str_starts_with($val, 'http://localhost')) {
                    $mixtes[] = $val;
                }
            }
        };
        $checkMixed($xp->query('//img/@src'), 'src');
        $checkMixed($xp->query('//script/@src'), 'src');
        $checkMixed($xp->query('//link[@rel="stylesheet"]/@href'), 'href');
        $checkMixed($xp->query('//iframe/@src'), 'src');
        $mixtes = array_unique(array_slice($mixtes, 0, 10));

        if ($mixtes) {
            $n = count($mixtes);
            $out[] = ind('mixte', 'Contenu mixte', 'warn',
                "Votre site est en HTTPS, mais {$n} ressource" . ($n > 1 ? 's sont chargées' : ' est chargée') . " en HTTP non sécurisé. Le cadenas peut disparaître, et certains navigateurs bloquent ces éléments.",
                "Remplacer les adresses http:// par https:// dans le contenu du site.",
                ['detail' => $mixtes]
            );
        } else {
            $out[] = ind('mixte', 'Contenu mixte', 'ok',
                "Toutes les ressources de la page sont chargées en HTTPS. Pas de contenu mixte.");
        }
    } else {
        $out[] = ind('mixte', 'Contenu mixte', 'na',
            "Impossible d'analyser le contenu de cette page.");
    }

    return $out;
}

/* ===========================================================
   PILLAR 3 — VISIBILITY
   =========================================================== */

function pillar_visibilite(array $home, string $origin): array
{
    $out  = [];
    $html = $home['body'];
    $xp   = dom_of($html);

    // --- 1. Site indexable ---
    $bloque = [];
    if ($xp) {
        $robots = meta_content($xp, 'robots');
        if ($robots && stripos($robots, 'noindex') !== false) {
            $bloque[] = 'une balise « noindex » dans le code de la page';
        }
    }
    if (!empty($home['headers']['x-robots-tag']) && stripos($home['headers']['x-robots-tag'], 'noindex') !== false) {
        $bloque[] = 'un en-tête « noindex » envoyé par le serveur';
    }
    $rob = http_fetch($origin . '/robots.txt', ['follow' => true, 'max' => 20_000]);
    if ($rob['status'] === 200 && preg_match('~^\s*User-agent:\s*\*\s*$\s*^\s*Disallow:\s*/\s*$~mi', $rob['body'])) {
        $bloque[] = 'un fichier robots.txt qui interdit tout le site';
    }

    if ($bloque) {
        $out[] = ind('indexable', 'Site indexable', 'fail',
            "Votre site demande à Google de ne pas l'afficher (" . implode(', ', $bloque) . "). Il est donc invisible dans les résultats de recherche, quoi que vous fassiez par ailleurs.",
            "C'est presque toujours la case « Demander aux moteurs de recherche de ne pas indexer ce site », restée cochée depuis la mise en ligne. À décocher immédiatement.",
            ['detail' => $bloque]
        );
    } else {
        $out[] = ind('indexable', 'Site indexable', 'ok',
            'Rien n\'empêche Google d\'afficher votre site dans ses résultats.');
    }

    // --- 2. Title + description (with the real Google preview) ---
    $titre = null;
    if ($xp) {
        $n = $xp->query('//title');
        if ($n && $n->length) {
            $titre = trim($n->item(0)->textContent);
        }
    }
    $desc = $xp ? meta_content($xp, 'description') : null;

    $apercu = [
        'url'         => $home['url'],
        'titre'       => $titre,
        'description' => $desc,
    ];

    $problemes = [];
    if (!$titre)                        { $problemes[] = "votre page n'a aucun titre"; }
    elseif (mb_strlen($titre) < 15)     { $problemes[] = 'votre titre est trop court pour dire ce que vous faites'; }
    elseif (mb_strlen($titre) > 65)     { $problemes[] = 'votre titre sera coupé en plein milieu par Google'; }

    if (!$desc)                         { $problemes[] = 'votre page n\'a pas de description, Google en invente une'; }
    elseif (mb_strlen($desc) > 165)     { $problemes[] = 'votre description sera coupée'; }

    if (!$titre || !$desc) {
        $out[] = ind('snippet', 'Titre et description', 'fail',
            'Voici exactement ce que voit un client dans Google : ' . implode(', ', $problemes) . '.',
            "Écrire un titre qui dit votre métier et votre ville, et une description qui donne envie de cliquer.",
            ['apercu' => $apercu]
        );
    } elseif ($problemes) {
        $out[] = ind('snippet', 'Titre et description', 'warn',
            'Voici ce que voit un client dans Google. À corriger : ' . implode(', ', $problemes) . '.',
            'Viser 55 caractères pour le titre, 150 pour la description.',
            ['apercu' => $apercu]
        );
    } else {
        $out[] = ind('snippet', 'Titre et description', 'ok',
            'Voici ce que voit un client dans Google. Titre et description sont bien présents, aux bonnes longueurs.',
            '', ['apercu' => $apercu]
        );
    }

    // --- 3. Readable business listing (schema.org) ---
    $fiche = null;
    if ($xp) {
        foreach ($xp->query('//script[@type="application/ld+json"]') ?: [] as $node) {
            $data = json_decode(trim($node->textContent), true);
            if (!is_array($data)) {
                continue;
            }
            $graph = $data['@graph'] ?? [$data];
            foreach ((array) $graph as $item) {
                if (!is_array($item) || empty($item['@type'])) {
                    continue;
                }
                $types = (array) $item['@type'];
                foreach ($types as $t) {
                    if (stripos((string) $t, 'LocalBusiness') !== false
                        || in_array($t, ['Restaurant', 'Store', 'Hotel', 'LodgingBusiness', 'BedAndBreakfast',
                                          'HealthAndBeautyBusiness', 'HairSalon', 'Organization'], true)) {
                        $fiche = $item;
                        break 3;
                    }
                }
            }
        }
    }

    if (!$fiche) {
        $out[] = ind('fiche', 'Fiche établissement', 'fail',
            "Google ne sait pas que vous êtes une entreprise locale, ni où vous vous trouvez. Vous perdez les recherches « près de chez moi » et la fiche à droite des résultats.",
            "Déclarer votre adresse, votre téléphone et vos horaires dans le code du site. Certains plugins SEO le proposent en option, sinon c'est un petit travail de code."
        );
    } else {
        $manque = [];
        if (empty($fiche['address']))       { $manque[] = 'adresse'; }
        if (empty($fiche['telephone']))     { $manque[] = 'téléphone'; }
        if (empty($fiche['openingHours']) && empty($fiche['openingHoursSpecification'])) { $manque[] = 'horaires'; }

        if (!$manque) {
            $out[] = ind('fiche', 'Fiche établissement', 'ok',
                'Google sait qui vous êtes, où vous êtes, et quand vous êtes ouvert.');
        } else {
            $out[] = ind('fiche', 'Fiche établissement', 'warn',
                'Google vous identifie comme une entreprise, mais il lui manque : ' . implode(', ', $manque) . '.',
                'Compléter ces informations pour apparaître dans les recherches locales.',
                ['detail' => ['manque' => $manque]]
            );
        }
    }

    // --- 4. Share preview (Open Graph) ---
    $ogTitre = $xp ? meta_content($xp, 'og:title', 'property') : null;
    $ogImg   = $xp ? meta_content($xp, 'og:image', 'property') : null;
    $ogDesc  = $xp ? meta_content($xp, 'og:description', 'property') : null;

    $partage = [
        'domaine'     => parse_url($home['url'], PHP_URL_HOST),
        'titre'       => $ogTitre ?: $titre,
        'description' => $ogDesc ?: $desc,
        'image'       => $ogImg ? absolutize($ogImg, $home['url']) : null,
    ];

    if (!$ogImg) {
        $out[] = ind('partage', 'Aperçu au partage', 'fail',
            "Quand quelqu'un partage votre site sur Facebook, WhatsApp ou LinkedIn, il n'y a pas d'image — juste un rectangle gris. Voilà à quoi ressemble votre site quand on vous recommande.",
            "Choisir une image de partage — c'est un simple champ de votre plugin SEO ou des réglages du site : une photo de votre établissement, pas votre logo sur fond blanc.",
            ['partage' => $partage]
        );
    } elseif (!$ogTitre) {
        $out[] = ind('partage', 'Aperçu au partage', 'warn',
            "Votre image de partage est en place, mais pas le titre qui l'accompagne.",
            'Compléter le titre de partage.',
            ['partage' => $partage]
        );
    } else {
        $out[] = ind('partage', 'Aperçu au partage', 'ok',
            'Voilà à quoi ressemble votre site quand on le partage. Image et titre sont bien en place.',
            '', ['partage' => $partage]
        );
    }

    return $out;
}

/* ===========================================================
   SCORE
   =========================================================== */

/** ok = 1, warn = 0.5, fail = 0. `na` values are excluded from the score. */
function pillar_score(array $indicateurs): ?int
{
    $poids = ['ok' => 1.0, 'warn' => 0.5, 'fail' => 0.0];
    $somme = 0.0;
    $n     = 0;
    foreach ($indicateurs as $i) {
        if (isset($poids[$i['status']])) {
            $somme += $poids[$i['status']];
            $n++;
        }
    }
    return $n === 0 ? null : (int) round(100 * $somme / $n);
}

/* ===========================================================
   PILLAR 4 — PERFORMANCE (shared with pagespeed.php)
   -----------------------------------------------------------
   Extracted here so the public client (pagespeed.php) and the
   private expert report (report.php) run the exact same code.
   =========================================================== */

/**
 * The Performance pillar via PageSpeed Insights. Returns the 4 indicators,
 * each carrying its factual `detail` (raw numbers) alongside the client verdict.
 * On API failure, returns null so the caller can decide how to degrade.
 */
function pillar_performance(string $url, array $config): ?array
{
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
        return null;
    }

    $data   = json_decode($api['body'], true) ?: [];
    $lh     = $data['lighthouseResult'] ?? [];
    $audits = $lh['audits'] ?? [];

    $score = $lh['categories']['performance']['score'] ?? null;
    $score = $score === null ? null : (int) round($score * 100);

    $lcpMs = $audits['largest-contentful-paint']['numericValue'] ?? null;
    $poids = $audits['total-byte-weight']['numericValue'] ?? null;

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
            ['valeur' => $score, 'fait' => "{$score}/100 (mobile)"]
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
            ['valeur' => round($lcpMs / 1000, 1), 'fait' => 'LCP ' . $s((float) $lcpMs)]
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
            ['valeur' => round($poids / 1_048_576, 1), 'fait' => $mo((float) $poids)]
        );
    }

    // --- 4. Images to compress ---
    if ($gainImages < 50_000) {
        $ind[] = ind('images', 'Images à alléger', 'ok',
            'Vos images sont correctement compressées. Rien à gagner de ce côté.',
            '', ['fait' => 'gain < 0,1 Mo']);
    } else {
        $st = $gainImages > 1_000_000 ? 'fail' : 'warn';
        $ind[] = ind('images', 'Images à alléger', $st,
            "Vos images peuvent être allégées de " . $mo((float) $gainImages) . " sans aucune perte visible.",
            "Compresser les photos et les servir au format WebP. C'est le gain le plus rapide à obtenir sur un site.",
            ['valeur' => round($gainImages / 1_048_576, 1), 'fait' => 'gain ' . $mo((float) $gainImages)]
        );
    }

    return $ind;
}

/**
 * Expert-only: best-effort WordPress version sniff.
 *
 * Deliberately EXCLUDED from the public client tool (rule 1: what cannot be
 * measured reliably from outside returns `na`, never a verdict). The version
 * is often masked by a cache or a security plugin. Surfaced here only for the
 * private/expert view, always flagged "à confirmer".
 */
function wp_version_sniff(array $home, string $origin): array
{
    $out = ['version' => null, 'source' => null, 'confiance' => 'à confirmer'];
    $html = $home['body'];

    // 1. generator meta tag (the cleanest signal when not stripped)
    if (preg_match('~name="generator"\s+content="WordPress\s+([\d.]+)~i', $html, $m)) {
        return ['version' => $m[1], 'source' => 'meta generator', 'confiance' => 'à confirmer'];
    }

    // 2. RSS feed generator (<generator>https://wordpress.org/?v=6.5</generator>)
    $feed = http_fetch($origin . '/feed/', ['follow' => true, 'max' => 40_000, 'timeout' => 5]);
    if ($feed['status'] === 200 && preg_match('~wordpress\.org/\?v=([\d.]+)~i', $feed['body'], $m)) {
        return ['version' => $m[1], 'source' => 'flux RSS', 'confiance' => 'à confirmer'];
    }

    // 3. readme.html (older installs leave it exposed)
    $readme = http_fetch($origin . '/readme.html', ['follow' => true, 'max' => 40_000, 'timeout' => 5]);
    if ($readme['status'] === 200 && preg_match('~Version\s+([\d.]+)~i', $readme['body'], $m)) {
        return ['version' => $m[1], 'source' => 'readme.html', 'confiance' => 'à confirmer'];
    }

    return $out;
}
