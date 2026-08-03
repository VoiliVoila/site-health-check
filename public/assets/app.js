/* Site health check — front end
 *
 * Flow:
 *   t0    start the result-free analysis thread and fire PageSpeed
 *   during first scans, the two visible pillars fill in as results arrive
 *         → the last two pillars continue in the same thread, without results
 *   end   the email unlocks the last two and reveals the global score
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
  attente: '',
  revealRun: 0,
  revealData: {},
};

const PILIERS_SEQUENCE = [
  {
    id: 'visibilite',
    numero: '01',
    titre: 'Visibilité',
    question: 'Google et vos clients vous trouvent-ils ?',
    verrouille: false,
    indicateurs: [
      'Site indexable',
      'Titre et description',
      'Fiche établissement',
      'Aperçu au partage',
    ],
  },
  {
    id: 'securite',
    numero: '02',
    titre: 'Sécurité',
    question: 'Votre site est-il une porte ouverte ?',
    verrouille: false,
    indicateurs: [
      'Cadenas valide',
      'Identifiants visibles',
      'Page de connexion',
      'Fichiers oubliés',
      'Sécurité navigation',
    ],
  },
  {
    id: 'entretien',
    numero: '03',
    titre: 'Entretien',
    question: "Est-ce que quelqu'un s'en occupe ?",
    verrouille: true,
    indicateurs: [
      'Liens et images',
      'Code à jour',
      'Dernière mise à jour',
      'Contenu mixte',
    ],
  },
  {
    id: 'performance',
    numero: '04',
    titre: 'Performance',
    question: 'Vos visiteurs attendent-ils ?',
    verrouille: true,
    indicateurs: [
      'Score mobile',
      "Vitesse d'affichage",
      'Poids de la page',
      'Images à alléger',
    ],
  },
];

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
  const classeNouveau = p.verrouille && etat.deverrouille ? 'pilier-a-revele' : '';
  const score = p.score === null
    ? '<small>non mesuré</small>'
    : `${p.score}<small>/100</small>`;

  return `<section class="pilier ${verrou ? 'pilier-verrouille' : ''} ${classeNouveau}" id="pilier-${p.id}">
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
  const visibles = etat.deverrouille ? etat.piliers : [];
  $('#piliers').innerHTML = visibles.map(rendPilier).join('') + (etat.attente || '');
}

function attendre(texte) {
  etat.attente = texte
    ? `<div class="attente"><span class="rotor"></span><span>${echappe(texte)}</span></div>`
    : '';
  peindre();
}

/* ---------- Result-free analysis reveal ---------- */

function rendAnalyseLigne(label, index) {
  return `<div class="analyse-ligne" data-analyse-ligne="${index}">
    <span class="analyse-ligne-marque" aria-hidden="true"><span class="analyse-mini-rotor"></span></span>
    <div class="analyse-ligne-corps">
      <div class="analyse-ligne-entete">
        <span class="analyse-ligne-label">${echappe(label)}</span>
        <span class="analyse-ligne-etat">À suivre</span>
      </div>
    </div>
  </div>`;
}

function rendAnalysePilier(p) {
  return `<article class="analyse-pilier" data-analyse-pilier="${p.id}" data-etat="a-venir">
    <div class="analyse-pilier-attente">
      <div class="analyse-pilier-tete">
        <div class="analyse-pilier-numero">${p.numero}</div>
        <div>
          <h3>${echappe(p.titre)}</h3>
          <p>${echappe(p.question)}</p>
        </div>
        <span class="analyse-pilier-badge">À venir</span>
      </div>
      <div class="analyse-liste">
        ${p.indicateurs.map(rendAnalyseLigne).join('')}
      </div>
    </div>
    <div class="analyse-pilier-resultat" hidden></div>
  </article>`;
}

function afficheAnalyse() {
  const root = $('#analyse-reveal');
  root.innerHTML = `<div class="analyse-introduction">
    <div class="analyse-signal" aria-hidden="true"><span></span></div>
    <div>
      <p class="analyse-kicker">Analyse en cours</p>
      <h2>On déroule les contrôles, un par un</h2>
      <p id="analyse-statut">Nous commençons par les premiers contrôles.</p>
    </div>
  </div>
  <div class="analyse-piliers">
    ${PILIERS_SEQUENCE.map(rendAnalysePilier).join('')}
  </div>
  <p class="analyse-note">Les deux premiers piliers se révèlent ici avec leurs vrais résultats. Les deux derniers restent réservés jusqu'à la fin.</p>`;
  root.hidden = false;
  root.setAttribute('aria-busy', 'true');
}

function configAnalyse(id) {
  return PILIERS_SEQUENCE.find((p) => p.id === id);
}

function carteAnalyse(id) {
  return document.querySelector(`[data-analyse-pilier="${id}"]`);
}

function ligneAnalyse(id, index) {
  return carteAnalyse(id)?.querySelector(`[data-analyse-ligne="${index}"]`);
}

function statutAnalyse(id, etatLigne) {
  const ligne = ligneAnalyse(id, etatLigne.index);
  if (!ligne) return;
  ligne.dataset.etat = etatLigne.etat;
  ligne.classList.toggle('est-visible', etatLigne.etat !== 'a-venir');
  ligne.classList.toggle('est-active', etatLigne.etat === 'en-cours');
  ligne.classList.toggle('est-terminee', etatLigne.etat === 'terminee');
  const libelle = ligne.querySelector('.analyse-ligne-etat');
  if (libelle) {
    libelle.textContent = etatLigne.etat === 'en-cours'
      ? 'Réflexion…'
      : etatLigne.etat === 'terminee' ? 'Contrôle parcouru' : 'À suivre';
  }
}

function statutCarteAnalyse(id, etatCarte) {
  const carte = carteAnalyse(id);
  if (!carte) return;
  const config = configAnalyse(id);
  carte.dataset.etat = etatCarte;
  const badge = carte.querySelector('.analyse-pilier-attente .analyse-pilier-badge');
  if (badge) {
    badge.textContent = etatCarte === 'en-cours'
      ? 'En cours'
      : etatCarte === 'terminee'
        ? config?.verrouille ? 'Résultats réservés' : 'Contrôles parcourus'
        : 'À venir';
  }
}

function reveleResultatAnalyse(id) {
  const carte = carteAnalyse(id);
  const config = configAnalyse(id);
  const resultat = etat.revealData[id];
  if (!carte || !config || config.verrouille || !resultat) return;
  if (carte.dataset.sequenceTerminee !== 'true') return;

  const attente = carte.querySelector('.analyse-pilier-attente');
  const resultatZone = carte.querySelector('.analyse-pilier-resultat');
  if (!resultatZone || resultatZone.dataset.affiche === 'true') return;

  if (attente) attente.hidden = true;
  resultatZone.innerHTML = rendPilier({ ...resultat, verrouille: false });
  resultatZone.dataset.affiche = 'true';
  resultatZone.hidden = false;
  carte.dataset.etat = 'revelee';
}

function actualiseCarteAnalyse(id) {
  const carte = carteAnalyse(id);
  if (!carte) return;
  const sequenceTerminee = carte.dataset.sequenceTerminee === 'true';
  if (!sequenceTerminee) return;
  statutCarteAnalyse(id, 'terminee');
  reveleResultatAnalyse(id);
}

function suitPilierAnalyse(id, reduit) {
  carteAnalyse(id)?.scrollIntoView({
    behavior: reduit ? 'auto' : 'smooth',
    block: 'start',
  });
}

function pauseAnalyse(duree) {
  return new Promise((resolve) => setTimeout(resolve, duree));
}

async function animeAnalyse(run) {
  const reduit = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const dureeEtape = reduit ? 180 : 420;
  const pauseEntreLignes = reduit ? 15 : 80;

  for (const pilier of PILIERS_SEQUENCE) {
    if (run !== etat.revealRun) return;
    suitPilierAnalyse(pilier.id, reduit);
    statutCarteAnalyse(pilier.id, 'en-cours');
    const statut = $('#analyse-statut');
    if (statut) statut.textContent = `Nous parcourons les contrôles du pilier « ${pilier.titre} ».`;

    for (let index = 0; index < pilier.indicateurs.length; index += 1) {
      if (run !== etat.revealRun) return;
      statutAnalyse(pilier.id, { index, etat: 'en-cours' });
      await pauseAnalyse(dureeEtape);
      if (run !== etat.revealRun) return;
      statutAnalyse(pilier.id, { index, etat: 'terminee' });
      await pauseAnalyse(pauseEntreLignes);
    }

    const carte = carteAnalyse(pilier.id);
    if (carte) carte.dataset.sequenceTerminee = 'true';
    actualiseCarteAnalyse(pilier.id);
    if (pilier !== PILIERS_SEQUENCE.at(-1)) {
      await pauseAnalyse(reduit ? 60 : 850);
      if (run !== etat.revealRun) return;
    }
  }

  if (run === etat.revealRun) {
    const statut = $('#analyse-statut');
    if (statut) statut.textContent = 'Les contrôles sont parcourus. Nous préparons votre bilan complet.';
    $('#analyse-reveal').setAttribute('aria-busy', 'false');
  }
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
  etat.attente = '';
  etat.revealData = {};
  etat.revealRun += 1;
  etat.url = url;
  $('#global').hidden = true;
  $('#verrou').hidden = true;
  $('#analyse-reveal').hidden = true;
  $('#analyse-reveal').innerHTML = '';
  $('#site-url').textContent = 'Analyse en cours…';
  $('#badge-wp').hidden = true;
  peindre();

  // PageSpeed starts now, in the background. We do not await it here.
  const pagespeed = post('pagespeed.php', { url }).catch(() => null);
  afficheAnalyse();
  const revealRun = etat.revealRun;
  const revealSequence = animeAnalyse(revealRun);
  $('#analyse-reveal').scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    // The analysis thread starts immediately. The first two responses fill
    // their results as soon as they arrive; the last two stay result-free.
    const visi = await post('scan.php', { url, groupe: 'visibilite' });
    $('#site-url').textContent = visi.url;
    $('#badge-wp').hidden = !visi.wordpress;
    etat.piliers.push(...visi.piliers.map((p) => ({ ...p, verrouille: false })));
    etat.revealData.visibilite = visi.piliers[0] || null;
    peindre();
    actualiseCarteAnalyse('visibilite');

    const secu = await post('scan.php', { url, groupe: 'securite' });
    etat.piliers.push(...secu.piliers.map((p) => ({ ...p, verrouille: false })));
    etat.revealData.securite = secu.piliers[0] || null;
    peindre();
    actualiseCarteAnalyse('securite');

    // The last two pillars are analysed while their controls are staged.
    const entretienPromise = post('scan.php', { url, groupe: 'entretien' });

    const [entretien, perf] = await Promise.all([entretienPromise, pagespeed]);
    etat.piliers.push(...entretien.piliers.map((p) => ({ ...p, verrouille: true })));
    etat.revealData.entretien = entretien.piliers[0] || null;
    actualiseCarteAnalyse('entretien');

    if (perf && perf.piliers) {
      etat.piliers.push(...perf.piliers.map((p) => ({ ...p, verrouille: true })));
    }
    etat.revealData.performance = perf?.piliers?.[0] || null;
    actualiseCarteAnalyse('performance');

    await revealSequence;
    const statutAnalyseFinal = $('#analyse-statut');
    if (statutAnalyseFinal) statutAnalyseFinal.textContent = 'Les contrôles sont parcourus. Nous préparons votre bilan complet.';
    $('#verrou').hidden = false;
  } catch (err) {
    etat.revealRun += 1;
    attendre(null);
    $('#analyse-reveal').hidden = true;
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

    $('#verrou').hidden = true;
    $('#analyse-reveal').hidden = true;
    $('#analyse-reveal').innerHTML = '';
    peindre();
    const revele = [...document.querySelectorAll('.pilier-a-revele')];
    revele.forEach((el) => el.classList.add('revele'));
    setTimeout(() => document.querySelectorAll('.pilier-a-revele').forEach((el) => el.classList.remove('pilier-a-revele', 'revele')), 1450);

    afficheGlobal();
    (revele[0] || $('#global')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    $('#erreur-email').textContent = err.message;
    $('#erreur-email').hidden = false;
  } finally {
    $('#deverrouiller').disabled = false;
  }
});
