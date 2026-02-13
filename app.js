/* ============================================================
   ACN + MITRE ENRICHED + CVE KEV + KILLCHAIN VIEWER
   - Tabs (macrocategorie) nel corpo centrale
   - Accordion (predicati) con Badge KEV dinamici
============================================================ */

let acn = null;
let enriched = null;
let mitreEnriched = null; // Mapping con nomi tecniche
let cve = null;
let kevList = []; // Lista delle CVE sfruttate attivamente (CISA KEV)
let killchain = null;

// Modalità accordion: solo UNA sezione aperta per volta
const SINGLE_OPEN_MODE = true;

/* ---------------------------
   LOAD JSON FILES
---------------------------- */
async function loadData() {
  try {
    // Caricamento parallelo di tutti i file (inclusi i nuovi arricchiti)
    const [acnRes, enrichedRes, mitreRes, cveRes, kevRes, killchainRes] = await Promise.all([
      fetch("machinetag.json").then(r => r.json()),
      fetch("acn_enriched.json").then(r => r.json()),
      fetch("mitre_mapping_enriched.json").then(r => r.json()),
      fetch("cve_mapping.json").then(r => r.json()),
      fetch("cisa_kev_list.json").then(r => r.json()).catch(() => []), // Fallback se il bot non ha ancora girato
      fetch("killchain_mapping.json").then(r => r.json())
    ]);

    acn = acnRes;
    enriched = enrichedRes;
    mitreEnriched = mitreRes;
    cve = cveRes;
    kevList = kevRes;
    killchain = killchainRes;

    buildMacroTabs();
    // Seleziona la prima macro di default (Baseline Characterization)
    const firstMacro = Object.keys(enriched.macro_categories)[0] || "BC";
    selectMacroTab(firstMacro);
    
  } catch (error) {
    console.error("Errore nel caricamento dei dati:", error);
    document.getElementById("tabContent").innerHTML = `
      <div style="padding:20px; color:#b30000;">
        <h3>Errore di caricamento</h3>
        <p>Assicurati che i file JSON siano presenti nel repository e che le GitHub Actions abbiano girato correttamente.</p>
      </div>`;
  }
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
    if (!macro) return;
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
  document.querySelectorAll(".macro-tab").forEach(b => {
    b.setAttribute("aria-selected", b.dataset.macro === code ? "true" : "false");
  });

  const container = document.getElementById("tabContent");
  container.innerHTML = "";

  const predKeys = enriched.macro_categories[code].predicates;
  const preds = acn.predicates.filter(p => predKeys.includes(p.value));

  preds.forEach(pred => {
    container.appendChild(buildPredicateSection(pred));
  });
}

/* ============================================================
   PREDICATE SECTION (Accordion)
============================================================ */
function buildPredicateSection(pred) {
  const section = document.createElement("section");
  section.className = "pred-section";
  
  // Trova i valori nel machinetag
  const entries = pred.entries || []; 
  const entryCount = entries.length;

  const header = document.createElement("button");
  header.className = "pred-header";
  header.type = "button";
  header.setAttribute("aria-expanded", "false");
  header.innerHTML = `
    <span>
      ${escapeHTML(pred.expanded)}
      <span class="count-badge">${entryCount}</span>
    </span>
    <span class="chevron">▶</span>
  `;

  const panel = document.createElement("div");
  panel.className = "pred-panel";
  panel.hidden = true;

  header.addEventListener("click", () => {
    const isOpen = header.getAttribute("aria-expanded") === "true";
    if (SINGLE_OPEN_MODE) {
      header.closest(".tab-content")
        .querySelectorAll(".pred-header[aria-expanded='true']")
        .forEach(h => { if (h !== header) togglePredicate(h, false); });
    }
    togglePredicate(header, !isOpen);
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
  if (open) { panel.hidden = false; panel.classList.add("open"); }
  else { panel.classList.remove("open"); panel.hidden = true; }
}

/* ============================================================
   RENDER PANEL CONTENT
============================================================ */
function renderPredicatePanel(pred, panel) {
  panel.innerHTML = "";

  // Summary section
  const summary = document.createElement("div");
  summary.className = "predicate-summary";
  summary.innerHTML = buildSummaryHTML(pred);
  panel.appendChild(summary);

  // Info Blocks (MITRE, CVE con KEV, KillChain)
  const info = document.createElement("section");
  info.className = "predicate-info";

  const mBlock = buildMitreBlock(pred.value);
  if (mBlock) info.insertAdjacentHTML('beforeend', mBlock);

  const cBlock = buildCveBlock(pred.value);
  if (cBlock) info.insertAdjacentHTML('beforeend', cBlock);

  const kBlock = buildKillChainBlock(pred.value);
  if (kBlock) info.insertAdjacentHTML('beforeend', kBlock);

  if (info.children.length > 0) panel.appendChild(info);

  // Entries (Values)
  if (pred.entries && pred.entries.length > 0) {
    const valuesDiv = document.createElement("div");
    valuesDiv.className = "values";
    pred.entries.forEach(val => {
      const card = document.createElement("div");
      card.className = "value-card";
      if (val.colour) card.style.borderLeft = `6px solid ${val.colour}`;
      card.innerHTML = `
        <h3>${escapeHTML(val.expanded)}</h3>
        <div class="value-meta">Codice: ${escapeHTML(val.value)}</div>
        <div class="value-desc">${escapeHTML(val.description || "Nessuna descrizione disponibile.")}</div>
      `;
      valuesDiv.appendChild(card);
    });
    panel.appendChild(valuesDiv);
  }
}

/* ============================================================
   BUILDERS
============================================================ */
function buildSummaryHTML(pred) {
  const macro = enriched.predicate_to_macro[pred.value];
  const macroName = enriched.macro_categories[macro]?.name || "N/A";
  const kcPhase = killchain[pred.value];

  return `
    <h3>${escapeHTML(pred.expanded)}</h3>
    <div class="macro">Macrocategoria: <strong>${escapeHTML(macroName)}</strong></div>
    <div class="badges">
      ${mitreEnriched[pred.value] ? '<span class="summary-badge mitre">MITRE ✓</span>' : ''}
      ${cve[pred.value]?.cve?.length > 0 ? '<span class="summary-badge cve">CVE ✓</span>' : ''}
      ${kcPhase ? `<span class="summary-badge kc">KillChain: ${escapeHTML(kcPhase)}</span>` : ''}
    </div>
  `;
}

function buildMitreBlock(predicate) {
  const data = mitreEnriched[predicate];
  if (!data || (data.core.length === 0 && data.related.length === 0)) return null;

  const renderTechs = (list) => list.map(t => 
    `<li><a href="https://attack.mitre.org/techniques/${t.id.split('.')[0]}/" target="_blank"><strong>${escapeHTML(t.id)}</strong></a>: ${escapeHTML(t.name)}</li>`
  ).join("");

  return `
    <div class="info-block mitre">
      <h4>Tecniche MITRE ATT&CK</h4>
      ${data.core.length > 0 ? `<ul>${renderTechs(data.core)}</ul>` : ''}
    </div>`;
}

function buildCveBlock(predicate) {
  const data = cve[predicate];
  if (!data || !data.cve || data.cve.length === 0) return null;

  let html = `<div class="info-block cve"><h4>Vulnerabilità CVE correlate (Kev Feed)</h4><ul>`;
  data.cve.forEach(id => {
    const isKev = kevList.includes(id);
    const url = `https://nvd.nist.gov/vuln/detail/${id}`;
    html += `
      <li>
        <a href="${url}" target="_blank"><strong>${escapeHTML(id)}</strong></a>
        ${isKev ? '<span class="badge-kev" title="Attivamente sfruttata in attacchi reali">Active Exploit</span>' : ''}
      </li>`;
  });
  html += `</ul></div>`;
  return html;
}

function buildKillChainBlock(predicate) {
  const phase = killchain[predicate];
  if (!phase || phase === "None") return null;
  return `<div class="info-block killchain"><h4>Kill Chain Phase</h4><p>${escapeHTML(phase)}</p></div>`;
}

function escapeHTML(str) {
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}