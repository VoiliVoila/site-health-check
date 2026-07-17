/* Site health check — front end
 *
 * Flow:
 *   t0    fire PageSpeed (10-30 s) AND the first scan at the same time
 *   ~1 s  Visibility shows in full, in clear (fast, concrete: the real site)
 *   ~10 s Security shows in full, in clear
 *   ~15 s Maintenance and Performance show: score visible, detail blurred
 *         → the email unlocks the last two and reveals the global score
 *
 * PageSpeed is the slow link. Firing it at t0 means that by the time the
 * visitor has read Visibility and Security, it is already back: the wait
 * becomes invisible.
 */

const API = 'api';
const $ = (sel) => document.querySelector(sel);

const etat = {
  url: null,
  piliers: [],       // { id, titre, question, score, indicateurs, verrouille }
  // (identifiers kept in French to match the API payload keys)
  deverrouille: false,
};

/* ---------- Requests ---------- */

async function post(endpoint, corps) {
  const r = await fetch(`${API}/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(corps),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Le test a échoué. Réessayez dans un instant.');
  return data;
}

/* ---------- Rendering ---------- */

const CLASSE_SCORE = (s) => (s === null ? '' : s >= 70 ? 's-ok' : s >= 40 ? 's-warn' : 's-fail');

const JAUGES = {
  ok:   `<svg class="jauge" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="#2F7D5D"/><path d="M6.5 11.4l3 3 6-6.4" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  warn: `<svg class="jauge" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="#E0A04D"/><path d="M11 5.5v7" stroke="#fff" stroke-width="2" stroke-linecap="round"/><circle cx="11" cy="16" r="1.3" fill="#fff"/></svg>`,
  fail: `<svg class="jauge" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="#B3392B"/><path d="M7.5 7.5l7 7M14.5 7.5l-7 7" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>`,
  na:   `<svg class="jauge" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="#D8D5CE"/><path d="M7 11h8" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>`,
};

const echappe = (s) => {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
};

/** The Google snippet, built from the real title and description. */
function rendApercuGoogle(a) {
  const chemin = (() => {
    try { return new URL(a.url).origin.replace(/^https?:\/\//, ''); }
    catch { return a.url; }
  })();
  const titre = a.titre
    ? echappe(a.titre.length > 65 ? a.titre.slice(0, 65) + '…' : a.titre)
    : '<span class="g-vide">Aucun titre — Google en choisira un au hasard</span>';
  const desc = a.description
    ? echappe(a.description.length > 165 ? a.description.slice(0, 165) + '…' : a.description)
    : '<span class="g-vide">Aucune description — Google prendra un bout de texte de votre page</span>';

  return `<div class="apercu">
    <p class="apercu-titre-bloc">Ce que voit un client dans Google</p>
    <div class="g-url">${echappe(chemin)}</div>
    <div class="g-titre">${titre}</div>
    <div class="g-desc">${desc}</div>
  </div>`;
}

/** The Facebook / WhatsApp share card, with the image or its absence. */
function rendCartePartage(p) {
  const image = p.image
    ? `<img class="carte-image" src="${echappe(p.image)}" alt="" loading="lazy"
            onerror="this.outerHTML='<div class=&quot;carte-image-vide&quot;>L’image de partage déclarée est introuvable</div>'">`
    : `<div class="carte-image-vide">Aucune image — un rectangle gris s’affichera</div>`;

  return `<div class="apercu" style="padding:16px">
    <p class="apercu-titre-bloc">Ce que voit un client quand on partage votre site</p>
    <div class="carte-partage">
      ${image}
      <div class="carte-texte">
        <div class="carte-domaine">${echappe(p.domaine || '')}</div>
        <div class="carte-titre">${echappe(p.titre || 'Sans titre')}</div>
      </div>
    </div>
  </div>`;
}

const NIVEAUX = {
  facile:    ['niv-facile',    'se corrige en 10 minutes'],
  technique: ['niv-technique', 'demande une main technique'],
};

function rendIndicateur(i) {
  const niv = NIVEAUX[i.niveau];
  const extras = [
    niv ? `<span class="ind-niveau ${niv[0]}">${niv[1]}</span>` : '',
    i.apercu  ? rendApercuGoogle(i.apercu)  : '',
    i.partage ? rendCartePartage(i.partage) : '',
    i.action  ? `<p class="ind-action">${echappe(i.action)}</p>` : '',
  ].join('');

  return `<div class="indicateur ${i.status === 'na' ? 'ind-na' : ''}">
    ${JAUGES[i.status] || JAUGES.na}
    <div class="ind-corps">
      <p class="ind-label">${echappe(i.label)}</p>
      <p class="ind-verdict">${echappe(i.verdict)}</p>
      ${extras}
    </div>
  </div>`;
}

function rendPilier(p) {
  const verrou = p.verrouille && !etat.deverrouille;
  const score = p.score === null
    ? '<small>non mesuré</small>'
    : `${p.score}<small>/100</small>`;

  return `<section class="pilier ${verrou ? 'pilier-verrouille' : ''}" id="pilier-${p.id}">
    <div class="pilier-tete">
      <div>
        <h2>${echappe(p.titre)}</h2>
      </div>
      <div class="pilier-score ${CLASSE_SCORE(p.score)}">${score}</div>
    </div>
    <p class="pilier-question">${echappe(p.question)}</p>
    ${p.indicateurs.map(rendIndicateur).join('')}
    ${verrou ? '<div class="voile"></div>' : ''}
  </section>`;
}

function peindre() {
  $('#piliers').innerHTML = etat.piliers.map(rendPilier).join('') + (etat.attente || '');
}

function attendre(texte) {
  etat.attente = texte
    ? `<div class="attente"><span class="rotor"></span><span>${echappe(texte)}</span></div>`
    : '';
  peindre();
}

/* ---------- Global score ---------- */

function scoreGlobal() {
  const notes = etat.piliers.map((p) => p.score).filter((s) => s !== null);
  if (!notes.length) return null;
  return Math.round(notes.reduce((a, b) => a + b, 0) / notes.length);
}

const PHRASES = [
  [80, 'Votre site est en bonne santé. Les quelques points orange ci-dessus valent le coup d’œil, sans urgence.'],
  [60, 'Votre site tient la route, mais plusieurs fondamentaux lui échappent. Rien d’irréversible.'],
  [40, 'Plusieurs points importants sont à reprendre. Commencez par les rouges : ce sont ceux qui vous coûtent des visiteurs.'],
  [0,  'Les fondamentaux ne sont pas en place. Ce n’est pas une question de réglages, c’est le socle du site qu’il faut reprendre.'],
];

function afficheGlobal() {
  const s = scoreGlobal();
  if (s === null) return;
  $('#global-valeur').textContent = s;
  $('#global-valeur').parentElement.className = `global-score ${CLASSE_SCORE(s)}`;
  $('#global-phrase').textContent = (PHRASES.find(([seuil]) => s >= seuil) || PHRASES.at(-1))[1];
  $('#global').hidden = false;
  $('#suite').hidden = false;
}

/* ---------- Flow ---------- */

$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = $('#url').value.trim();
  if (!url) return;

  $('#lancer').disabled = true;
  $('#erreur').hidden = true;
  $('#resultats').hidden = false;
  const apercu = $('#apercu-hero');
  if (apercu) apercu.hidden = true;
  etat.piliers = [];
  etat.deverrouille = false;
  etat.url = url;
  $('#global').hidden = true;
  $('#verrou').hidden = true;

  // PageSpeed starts now, in the background. We do not await it here.
  const pagespeed = post('pagespeed.php', { url }).catch(() => null);

  attendre('Nous consultons votre site…');

  try {
    // Visibility first: fast and concrete (their real site, the previews),
    // it fills the wait while Security runs its probes.
    const visi = await post('scan.php', { url, groupe: 'visibilite' });
    $('#site-url').textContent = visi.url;
    $('#badge-wp').hidden = !visi.wordpress;
    etat.piliers.push(...visi.piliers.map((p) => ({ ...p, verrouille: false })));
    attendre('Nous passons votre sécurité au crible…');

    const secu = await post('scan.php', { url, groupe: 'securite' });
    etat.piliers.push(...secu.piliers.map((p) => ({ ...p, verrouille: false })));
    attendre('Encore un instant, nous finissons le diagnostic…');

    // Maintenance and Performance: analysed, but detail reserved for the report.
    const entretien = await post('scan.php', { url, groupe: 'entretien' });
    etat.piliers.push(...entretien.piliers.map((p) => ({ ...p, verrouille: true })));

    const perf = await pagespeed;
    if (perf && perf.piliers) {
      etat.piliers.push(...perf.piliers.map((p) => ({ ...p, verrouille: true })));
    }

    attendre(null);
    $('#verrou').hidden = false;
    // Ease down to the first masked pillar (the teaser), not straight to the
    // email form — the visitor sees "there's more, blurred" and arrives gently.
    const premierMasque = document.querySelector('.pilier-verrouille');
    (premierMasque || $('#verrou')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    attendre(null);
    $('#erreur').textContent = err.message;
    $('#erreur').hidden = false;
  } finally {
    $('#lancer').disabled = false;
  }
});

$('#form-email').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#email').value.trim();
  const consent = $('#consent').checked;
  $('#erreur-email').hidden = true;

  if (!consent) {
    $('#erreur-email').textContent = 'Merci de cocher la case pour afficher votre bilan.';
    $('#erreur-email').hidden = false;
    return;
  }

  $('#deverrouiller').disabled = true;
  try {
    const resultats = etat.piliers.map((p) => ({
      id: p.id, titre: p.titre, score: p.score,
      indicateurs: p.indicateurs.map((i) => ({
        id: i.id, label: i.label, status: i.status, verdict: i.verdict,
      })),
    }));
    await post('lead.php', { email, url: etat.url, consent, resultats, score: scoreGlobal() });
    etat.deverrouille = true;

    // Reveal WITHOUT re-rendering, so the un-blur animates (CSS transition),
    // and flash the freshly revealed pillars so the unlock is felt.
    const revele = [...document.querySelectorAll('.pilier-verrouille')];
    revele.forEach((el) => {
      el.classList.remove('pilier-verrouille');
      el.classList.add('revele');
      el.querySelector('.voile')?.classList.add('fondu');
    });
    setTimeout(() => document.querySelectorAll('.voile').forEach((v) => v.remove()), 550);

    $('#verrou').hidden = true;
    afficheGlobal();
    // Move attention UP to the freshly revealed content — fixes "the view
    // stayed on the email box, I didn't realise everything had appeared".
    (revele[0] || $('#global')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    $('#erreur-email').textContent = err.message;
    $('#erreur-email').hidden = false;
  } finally {
    $('#deverrouiller').disabled = false;
  }
});
