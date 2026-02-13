/* ============================================================
   ACN + MITRE + CVE + KILLCHAIN VIEWER
   - Tabs (macrocategorie) nel corpo centrale
   - Accordion (predicati) single-open (Opzione A)
============================================================ */

let acn = null;
let enriched = null;
let mitre = null;
let cve = null;
let killchain = null;

// Modalità accordion: solo UNA sezione aperta per volta
const SINGLE_OPEN_MODE = true;

/* ---------------------------
   LOAD JSON FILES
---------------------------- */
async function loadData() {
  acn = await fetch("machinetag.json").then(r => r.json());
  enriched = await fetch("acn_enriched.json").then(r => r.json());
  mitre = await fetch("mitre_mapping.json").then(r => r.json());
  cve = await fetch("cve_mapping.json").then(r => r.json());
  killchain = await fetch("killchain_mapping.json").then(r => r.json());

  buildMacroTabs();
  // Seleziona la prima macro di default
  const firstMacro = ["BC","TT","TA","AC"][0];
  selectMacroTab(firstMacro);
}
loadData();

/* ============================================================
   MACRO TABS
============================================================ */
function buildMacroTabs() {
  const tabs = document.getElementById("macroTabs");
  tabs.innerHTML = "";

  const order = ["BC","TT","TA","AC"];
  order.forEach(code => {
    const macro = enriched.macro_categories[code];
    const btn = document.createElement("button");
    btn.className = "macro-tab";
    btn.type = "button";
    btn.role = "tab";
    btn.setAttribute("aria-selected", "false");
    btn.dataset.macro = code;
    btn.textContent = `${code} — ${macro.name}`;
    btn.addEventListener("click", () => selectMacroTab(code));
    tabs.appendChild(btn);
  });
}

function selectMacroTab(code) {
  // evidenzia tab
  document.querySelectorAll(".macro-tab").forEach(b => {
    b.setAttribute("aria-selected", b.dataset.macro === code ? "true" : "false");
  });

  // costruisci contenuto della tab
  const container = document.getElementById("tabContent");
  container.innerHTML = "";

  const predKeys = enriched.macro_categories[code].predicates;
  const preds = acn.predicates.filter(p => predKeys.includes(p.value));

  // Accordion: una sezione per predicato
  preds.forEach(pred => {
    container.appendChild(buildPredicateSection(pred));
  });

  // Apri la prima sezione per comodità (se esiste)
//   const firstHeader = container.querySelector(".pred-header");
//   if (firstHeader) firstHeader.click();
}

/* ============================================================
   PREDICATE SECTION (Accordion)
============================================================ */
function buildPredicateSection(pred) {
  const section = document.createElement("section");
  section.className = "pred-section";
  section.dataset.predicate = pred.value;
  const subset = acn.values.find(v => v.predicate === pred.value);
  const entryCount = subset?.entry?.length || 0;

  // Header
  const header = document.createElement("button");
  header.className = "pred-header";
  header.type = "button";
  header.setAttribute("aria-expanded", "false");
  header.innerHTML = `
    <span>
		${pred.expanded}
		<span class="count-badge" aria-label="Numero di valori">${entryCount}</span>
	</span>
    <span class="chevron">▶</span>
  `;

  // Panel (collassabile)
  const panel = document.createElement("div");
  panel.className = "pred-panel";
  panel.hidden = true;

  // Click = toggle (single-open se abilitatO)
  header.addEventListener("click", () => {
    const isOpen = header.getAttribute("aria-expanded") === "true";
    if (SINGLE_OPEN_MODE) {
      // Chiudi tutti gli altri della stessa tab
      header.closest(".tab-content")
        .querySelectorAll(".pred-header[aria-expanded='true']")
        .forEach(h => {
          if (h !== header) togglePredicate(h, false);
        });
    }
    togglePredicate(header, !isOpen);
    // Lazy render: se pannello appena aperto e vuoto, render contenuti
    if (!isOpen && panel.dataset.rendered !== "true") {
      renderPredicatePanel(pred, panel);
      panel.dataset.rendered = "true";
    }
  });

  section.appendChild(header);
  section.appendChild(panel);
  return section;
}

function togglePredicate(header, open) {
  header.setAttribute("aria-expanded", open ? "true" : "false");
  const panel = header.nextElementSibling;
  if (!panel) return;
  if (open) {
    panel.hidden = false;
    panel.classList.add("open");
  } else {
    panel.classList.remove("open");
    // Per mantenere lo stato "lazy", non svuoto l'HTML: nascondo soltanto
    panel.hidden = true;
  }
}

/* ============================================================
   RENDER CONTENUTO SEZIONE PREDICATO
   (summary + info + values)
============================================================ */
function renderPredicatePanel(pred, panel) {
  panel.innerHTML = ""; // sicurezza

  const subset = acn.values.find(v => v.predicate === pred.value);
  const entryCount = subset?.entry?.length || 0;

  // SUMMARY
  const summary = document.createElement("div");
  summary.className = "predicate-summary";
  summary.innerHTML = buildSummaryHTML(pred, subset);
  panel.appendChild(summary);

  // INFO (MITRE / CVE / KC) — SOLO SE CI SONO DATI
  const info = document.createElement("section");
  info.className = "predicate-info";

  const mitreBlock = buildMitreBlock(pred.value);
  if (mitreBlock) {
    const wrap = document.createElement("div");
    wrap.className = "info-block mitre";
    wrap.innerHTML = mitreBlock;
    info.appendChild(wrap);
  }

  const cveBlock = buildCveBlock(pred.value);
  if (cveBlock) {
    const wrap = document.createElement("div");
    wrap.className = "info-block cve";
    wrap.innerHTML = cveBlock;
    info.appendChild(wrap);
  }

  const kcBlock = buildKillChainBlock(pred.value);
  if (kcBlock) {
    const wrap = document.createElement("div");
    wrap.className = "info-block killchain";
    wrap.innerHTML = kcBlock;
    info.appendChild(wrap);
  }

  if (info.children.length > 0) panel.appendChild(info);

  // VALUES (cards)
  if (entryCount > 0) {
    const values = document.createElement("div");
    values.className = "values";
    subset.entry.forEach(val => {
      const card = document.createElement("div");
      card.className = "value-card";
      if (val.colour) card.style.borderLeft = `6px solid ${val.colour}`;
      card.innerHTML = `
        <h3>${escapeHTML(val.expanded)}</h3>
        <div class="value-meta">
          Codice: ${escapeHTML(val.value)}<br>
          UUID: ${escapeHTML(val.uuid || "—")}
        </div>
        <div class="value-desc">${escapeHTML(val.description || "")}</div>
      `;
      values.appendChild(card);
    });
    panel.appendChild(values);
  }
}

/* ============================================================
   SUMMARY (HTML)
============================================================ */
function buildSummaryHTML(pred, subset) {
  const macro = enriched.predicate_to_macro[pred.value];
  const macroName = enriched.macro_categories[macro]?.name || macro || "-";
  const entryCount = subset?.entry?.length || 0;

  const hasMitre = !!(mitre[pred.value] &&
    ((mitre[pred.value].core?.length || 0) > 0 ||
     (mitre[pred.value].related?.length || 0) > 0));

  const hasCVE = !!(cve[pred.value] &&
    Array.isArray(cve[pred.value].cve) &&
    cve[pred.value].cve.length > 0);

  const kcPhase = killchain[pred.value] || null;

  const badges = [];
  if (hasMitre) badges.push(`<div class="summary-badge mitre">MITRE ✓</div>`);
  if (hasCVE)   badges.push(`<div class="summary-badge cve">CVE ✓</div>`);
  if (kcPhase)  badges.push(`<div class="summary-badge kc">KillChain: ${escapeHTML(kcPhase)}</div>`);

  return `
    <h3>${escapeHTML(pred.expanded)}</h3>
    <div class="macro">Macrocategoria: <strong>${escapeHTML(macroName)} (${escapeHTML(macro || "–")})</strong></div>
    <div class="macro">Valori: <strong>${entryCount}</strong></div>
    <div class="badges">${badges.join("")}</div>
  `;
}

/* ============================================================
   INFO BLOCKS BUILDERS (return HTML string or null)
============================================================ */
function buildMitreBlock(predicate) {
  const map = mitre[predicate];
  if (!map) return null;

  const hasCore = Array.isArray(map.core) && map.core.length > 0;
  const hasRelated = Array.isArray(map.related) && map.related.length > 0;
  if (!hasCore && !hasRelated) return null;

  let html = `<h4>Tecniche MITRE ATT&CK correlate</h4>`;

  if (hasCore) {
    html += `<strong>Core:</strong><ul>`;
    map.core.forEach(id => {
      const url = `https://attack.mitre.org/techniques/${encodeURIComponent(id)}/`;
      html += `<li><a href="${url}" target="_blank" rel="noopener noreferrer">${escapeHTML(id)}</a></li>`;
    });
    html += `</ul>`;
  }

  if (hasRelated) {
    html += `<strong>Related:</strong><ul>`;
    map.related.forEach(id => {
      const url = `https://attack.mitre.org/techniques/${encodeURIComponent(id)}/`;
      html += `<li><a href="${url}" target="_blank" rel="noopener noreferrer">${escapeHTML(id)}</a></li>`;
    });
    html += `</ul>`;
  }

  return html;
}

function buildCveBlock(predicate) {
  const entry = cve[predicate];
  if (!entry || !entry.cve || entry.cve.length === 0) {
      return `<div class="info-block cve"><h4>CVE</h4><p style="color:var(--muted); font-size:12px;">Nessuna CVE critica recente trovata nel database attivo.</p></div>`;
  }

  let html = `<div class="info-block cve"><h4>Vulnerabilità CVE correlate</h4><ul>`;
  entry.cve.forEach(id => {
    const url = `https://nvd.nist.gov/vuln/detail/${id}`;
    html += `<li><a href="${url}" target="_blank" rel="noopener noreferrer">${escapeHTML(id)}</a></li>`;
  });
  html += `</ul></div>`;
  return html;
}

function buildKillChainBlock(predicate) {
  const phase = killchain[predicate];
  if (!phase) return null;
  return `
    <h4>Kill Chain Phase</h4>
    <p>${escapeHTML(phase)}</p>
  `;
}

/* ============================================================
   UTILS
============================================================ */
function escapeHTML(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* ============================================================
   (Opzionale) Ricerca globale – disabilitata in questa vista
   (Se servirà, possiamo aggiungere una barra di ricerca per tab)
============================================================ */

/* Fine file */