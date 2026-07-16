# Site Health Check

A public, no-signup tool that checks the **16+ fundamentals** of a website —
security, maintenance, visibility, performance — from the outside, without any
access to the site being tested. It runs each check live and reports every
finding as a plain-language consequence and a concrete next step, never a raw
metric.

Built as a lead magnet: the first pillars are shown for free, the full report is
unlocked with an email. The UI is in French (its intended audience); the code
and documentation are in English.

> **Status:** production-ready. Designed to run on its own (sub)domain
> (e.g. `audit.lajetee.fr`).

## What it checks

17 indicators — 4 per pillar, plus a 5th for security:

| Pillar | Indicators |
|--------|-----------|
| **Security** — *is your site an open door?* | valid padlock (HTTPS + expiry) · exposed usernames\* · exposed login page\* · forgotten files left accessible · modern browser protections (security headers) |
| **Maintenance** — *is anyone looking after it?* | server response time · broken links & images · admin scripts served to the public\* · frozen footer year |
| **Visibility** — *can Google and your clients find you?* | indexable · title + description (real Google preview) · readable business listing (schema.org) · share preview (real Open Graph card) |
| **Performance** — *are your visitors waiting?* | mobile score · largest contentful paint · page weight · images to compress |

\* WordPress-specific. On a non-WordPress site these fall back to *not
applicable* and the pillar is scored on the remaining indicators. The tool works
on any site.

### Three design rules

Every indicator must pass all three, without exception:

1. **Always measurable from the outside.** What cannot be reliably measured
   returns `na`, never a false failure. (This is why the WordPress *version* is
   not tested — it cannot be read reliably from outside.)
2. **A one-sentence consequence**, understandable without any technical
   background.
3. **It points to an action**, whether the owner does it themselves or not.

## Architecture

Plain PHP, no framework, no build step. Deploys to any shared host with PHP 8+.

```
site-health-check/
├── public/              ← web root: point the (sub)domain HERE
│   ├── index.html       front end
│   ├── assets/          style.css, app.js
│   └── api/             scan.php, pagespeed.php, lead.php
│                        expert.php, report.php   (private expert mode)
│                        (+ lib / checks / ratelimit internal includes)
├── audit-cli.php        ← expert report on the command line (JSON)
├── config.php           ← ABOVE the web root: API key + notification emails
└── data/                ← ABOVE the web root: leads.csv + rate-limit store
```

`config.php` and `data/` sit **above** `public/` on purpose: they must never be
web-reachable. The `.htaccess` in `api/` additionally denies direct access to
the internal include files.

The scan runs in stages so the UI can render progressively: the front end fires
the slow PageSpeed call first, in the background, then requests one pillar at a
time. By the time the visitor has read the first results, PageSpeed is back.

## Requirements

PHP 8.0+ with the `curl`, `dom`, `openssl` and `mbstring` extensions (all
standard). A free [PageSpeed Insights API key](https://console.cloud.google.com/apis/credentials)
for the Performance pillar — without it the shared anonymous quota runs out
almost immediately and that pillar degrades gracefully to "unavailable".

## Setup

1. Point your domain or subdomain at the **`public/`** directory (not the
   repository root).
2. Copy the config and fill it in:
   ```bash
   cp config.example.php config.php
   ```
   Set `pagespeed_key`, and optionally `notify_to` / `notify_from`.
3. Make sure `data/` is writable by PHP.

That's it. `config.php` and `data/` are gitignored and never leave your server.

### Local development

PHP's built-in server is enough (here via Docker):

```bash
docker run --rm -p 8000:8000 -v "$PWD":/app -w /app/public \
  php:8.3-cli php -S 0.0.0.0:8000
# → http://localhost:8000
```

Run the engine from the command line, without the UI:

```bash
docker run --rm -v "$PWD":/app -w /app php:8.3-cli php test-cli.php https://example.com
```

## Expert report (private)

The public tool reports each finding as a plain-language consequence. The **same
engine** can also emit an **expert report** that keeps the raw technical fact
behind every indicator (certificate issuer and expiry, exact security headers
missing, title/description lengths, detected CMS/platform, best-effort
WordPress version…), plus per-pillar and overall scores. One engine, two views:
change a check once and both follow.

Two ways to obtain it:

```bash
# Command line → JSON
docker run --rm -v "$PWD":/app -w /app php:8.3-cli php audit-cli.php https://example.com --perf

# HTTP endpoint (see gating below)
GET /api/expert.php?url=example.com&perf=1
```

**It is private by design.** An expert report lists exposed usernames, forgotten
files and the platform/version of sites that are not yours — effectively a
checklist for an attacker. `api/expert.php` therefore refuses every request that
is not either from the loopback interface or carrying a matching `expert_token`
(from `config.php` or the `EXPERT_TOKEN` env var). Do not expose it publicly.

## Security of the tool itself

The tool makes outbound requests to URLs supplied by strangers. Two guards:

- **Anti-SSRF** (`assert_public_host`): rejects any host that resolves to a
  private, loopback or link-local address (including cloud metadata endpoints).
  Revalidated on **every** redirect, since a redirect could otherwise bypass
  the check.
- **Rate limiting**: 20 scans per IP per hour (`ratelimit.php`).

Cross-origin requests are refused by default. Set the `CHECK_ALLOW_ORIGIN`
environment variable only if you serve the front end from a different origin
than the API.

## Data & privacy

`lead.php` requires explicit consent, stores only the email address, the tested
URL and a timestamp (as proof of consent), and never sends automated marketing.

## License

MIT.

---

Built by [La Jetée](https://lajetee.fr) — website creation and optimisation.
