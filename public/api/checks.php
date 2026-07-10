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

function ind(string $id, string $label, string $status, string $verdict, string $action = '', array $extra = []): array
{
    return array_merge([
        'id'      => $id,
        'label'   => $label,
        'status'  => $status,   // ok | warn | fail | na
        'verdict' => $verdict,
        'action'  => $action,
    ], $extra);
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
        $out[] = ind('protections', 'Protection navigateur', 'ok',
            "Toutes les protections que les navigateurs offrent gratuitement sont activées. C'est le réglage des sites bien tenus.",
            '', ['detail' => ['present' => $present]]
        );
    } elseif ($nProt >= 2) {
        $out[] = ind('protections', 'Protection navigateur', 'warn',
            "Une partie des protections navigateur sont en place, mais il en manque. Ce n'est pas une faille — c'est un réglage rapide que les sites soignés complètent.",
            "Ajouter les en-têtes de sécurité manquants — quelques lignes côté serveur, ou une case à activer dans Cloudflare.",
            ['detail' => ['present' => $present]]
        );
    } else {
        $out[] = ind('protections', 'Protection navigateur', 'fail',
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

    // --- 1. Server response time ---
    $ttfb = $home['ttfb'];
    $ms   = (int) round($ttfb * 1000);
    if ($ttfb > 1.2) {
        $out[] = ind('reponse', 'Temps de réponse', 'fail',
            "Votre hébergement met {$ms} millisecondes à répondre, avant même de commencer à afficher quoi que ce soit. Au-delà d'une seconde, les visiteurs mobiles abandonnent.",
            "C'est presque toujours l'hébergement ou l'absence de cache. Un cache bien réglé divise ce chiffre par cinq.",
            ['detail' => ['ttfb_ms' => $ms]]
        );
    } elseif ($ttfb > 0.6) {
        $out[] = ind('reponse', 'Temps de réponse', 'warn',
            "Votre serveur répond en {$ms} millisecondes. C'est honnête, sans plus.",
            "Activer un cache de pages ferait descendre ce chiffre nettement.",
            ['detail' => ['ttfb_ms' => $ms]]
        );
    } else {
        $out[] = ind('reponse', 'Temps de réponse', 'ok',
            "Votre serveur répond en {$ms} millisecondes. C'est rapide.", '',
            ['detail' => ['ttfb_ms' => $ms]]
        );
    }

    // --- 2. Broken links and images ---
    $soft = soft_404_baseline($origin);
    if (!$xp || $soft) {
        $out[] = ind('casses', 'Liens et images', 'na',
            "Impossible de tester les liens de façon fiable sur ce site.");
    } else {
        $urls = [];
        foreach ($xp->query('//a/@href') ?: [] as $n) {
            $u = absolutize($n->nodeValue, $home['url']);
            if ($u && str_starts_with($u, $origin)) {
                $urls[$u] = 'lien';
            }
        }
        foreach ($xp->query('//img/@src') ?: [] as $n) {
            $u = absolutize($n->nodeValue, $home['url']);
            if ($u && str_starts_with($u, $origin)) {
                $urls[$u] = 'image';
            }
        }
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

    // --- 3. Admin scripts served to the public (WordPress) ---
    if (!$isWp) {
        $out[] = ind('scripts_admin', "Scripts d'administration", 'na',
            "Cet indicateur ne concerne que les sites WordPress.");
    } else {
        $editeur = ['block-editor.min.js', 'wp-block-editor', 'blocks.min.js', 'rich-text.min.js', 'components.min.js'];
        $vus = array_values(array_filter($editeur, fn($s) => stripos($html, $s) !== false));

        if (count($vus) >= 2) {
            $out[] = ind('scripts_admin', "Scripts d'administration", 'fail',
                "Votre site envoie l'éditeur WordPress à chacun de vos visiteurs — près d'un mégaoctet de code dont ils n'ont aucun usage. C'est du temps de chargement pur perdu.",
                "Un plugin ou le thème charge ses fichiers d'édition sur le site public. Il faut les réserver à l'administration.",
                ['detail' => ['scripts' => $vus]]
            );
        } else {
            $out[] = ind('scripts_admin', "Scripts d'administration", 'ok',
                "Votre site ne charge pas de code d'administration inutile pour vos visiteurs.");
        }
    }

    // --- 4. Frozen footer year ---
    $pied = substr($html, -4000);
    if (preg_match_all('~(?:©|&copy;|copyright)\s*(?:-|–)?\s*((?:19|20)\d{2})~i', $pied, $m)) {
        $annees  = array_map('intval', $m[1]);
        $recente = max($annees);
        $courante = (int) date('Y');

        if ($recente < $courante - 1) {
            $ecart = $courante - $recente;
            $out[] = ind('pied', 'Pied de page', 'warn',
                "Le pied de page de votre site affiche encore « © {$recente} ». Un visiteur en déduit que le site est à l'abandon depuis {$ecart} ans.",
                "Remplacer l'année en dur par une année automatique — c'est cinq minutes.",
                ['detail' => ['annee' => $recente]]
            );
        } else {
            $out[] = ind('pied', 'Pied de page', 'ok',
                "L'année affichée en pied de page est à jour.",
                '', ['detail' => ['annee' => $recente]]
            );
        }
    } else {
        $out[] = ind('pied', 'Pied de page', 'na',
            "Aucune mention d'année en pied de page — rien à signaler.");
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
            "Déclarer votre adresse, votre téléphone et vos horaires dans le code du site — tous les plugins SEO le font."
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
            "Choisir une image de partage : une photo de votre établissement, pas votre logo sur fond blanc.",
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
