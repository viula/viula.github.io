/* ============================================================
   ACN VIEWER - FINAL STABLE VERSION
============================================================ */

let acn = null;
let enriched = null;
let mitreEnriched = null; 
let cve = null;
let kevList = []; 
let killchain = null;

const SINGLE_OPEN_MODE = true;

async function loadData() {
  try {
    // Carichiamo i file. Nota: usiamo mitre_mapping_enriched se esiste, altrimenti mitre_mapping
    const [acnRes, enrichedRes, mitreRes, cveRes, kevRes, killchainRes] = await Promise.all([
      fetch("machinetag.json").then(r => r.json()),
      fetch("acn_enriched.json").then(r => r.json()),
      fetch("mitre_mapping_enriched.json").then(r => r.json()).catch(() => fetch("mitre_mapping.json").then(r => r.json())),
      fetch("cve_mapping.json").then(r => r.json()),
      fetch("cisa_kev_list.json").then(r => r.json()).catch(() => []),
      fetch("killchain_mapping.json").then(r => r.json())
    ]);

    acn = acnRes;
    enriched = enrichedRes;
    mitreEnriched = mitreRes;
    cve = cveRes;
    kevList = kevRes;
    killchain = killchainRes;

    console.log("Dati caricati correttamente. Predicati trovati:", acn.predicates.length);

    buildMacroTabs();
    const firstMacro = Object.keys(enriched.macro_categories)[0] || "BC";
    selectMacroTab(firstMacro);
    
  } catch (error) {
    console.error("Errore nel caricamento:", error);
  }
}

loadData();

/* --- TABS --- */
function buildMacroTabs() {
  const tabs = document.getElementById("macroTabs");
  tabs.innerHTML = "";
  ["BC","TT","TA","AC"].forEach(code => {
    const macro = enriched.macro_categories[code];
    if (!macro) return;
    const btn = document.createElement("button");
    btn.className = "macro-tab";
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

/* --- ACCORDION --- */
function buildPredicateSection(pred) {
  const section = document.createElement("section");
  section.className = "pred-section";
  
  // TROVA I VALORI: Cerchiamo nell'array 'values' di machinetag.json
  const subset = acn.values.find(v => v.predicate === pred.value);
  const entryCount = subset?.entry?.length || 0;

  const header = document.createElement("button");
  header.className = "pred-header";
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
      document.querySelectorAll(".pred-header[aria-expanded='true']")
        .forEach(h => { if (h !== header) togglePredicate(h, false); });
    }
    togglePredicate(header, !isOpen);
    if (!isOpen && panel.dataset.rendered !== "true") {
      renderPredicatePanel(pred, panel, subset);
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
  panel.hidden = !open;
  if (open) panel.classList.add("open"); else panel.classList.remove("open");
}

/* --- RENDERING INTERNO --- */
function renderPredicatePanel(pred, panel, subset) {
  panel.innerHTML = "";

  // 1. Riepilogo
  const summary = document.createElement("div");
  summary.className = "predicate-summary";
  summary.innerHTML = buildSummaryHTML(pred);
  panel.appendChild(summary);

  // 2. Threat Intelligence
  const info = document.createElement("section");
  info.className = "predicate-info";

  const mBlock = buildMitreBlock(pred.value);
  if (mBlock) info.insertAdjacentHTML('beforeend', mBlock);

  const cBlock = buildCveBlock(pred.value);
  if (cBlock) info.insertAdjacentHTML('beforeend', cBlock);

  const kBlock = buildKillChainBlock(pred.value);
  if (kBlock) info.insertAdjacentHTML('beforeend', kBlock);

  if (info.children.length > 0) panel.appendChild(info);

  // 3. CARDS DEI VALORI (ITEM)
  if (subset && subset.entry && subset.entry.length > 0) {
    const valuesDiv = document.createElement("div");
    valuesDiv.className = "values";
    subset.entry.forEach(val => {
      const card = document.createElement("div");
      card.className = "value-card";
      if (val.colour) card.style.borderLeft = `6px solid ${val.colour}`;
      card.innerHTML = `
        <h3>${escapeHTML(val.expanded)}</h3>
        <div class="value-meta">Codice: <code>${escapeHTML(val.value)}</code></div>
        <div class="value-desc">${escapeHTML(val.description || "")}</div>
      `;
      valuesDiv.appendChild(card);
    });
    panel.appendChild(valuesDiv);
  } else {
    panel.insertAdjacentHTML('beforeend', '<p style="padding:10px; color:#999;">Nessun valore specifico trovato per questo predicato.</p>');
  }
}

/* --- HELPERS --- */
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
      ${kcPhase ? `<span class="summary-badge kc">${escapeHTML(kcPhase)}</span>` : ''}
    </div>`;
}

function buildMitreBlock(predicate) {
  const data = mitreEnriched[predicate];
  if (!data) return null;

  const renderItem = (t) => {
    const id = typeof t === 'string' ? t : t.id;
    const name = typeof t === 'string' ? "" : ` - ${escapeHTML(t.name)}`;
    
    // Generazione URL dinamico per MITRE ATT&CK
    // Se l'ID è T1566.001, diventa T1566/001/
    const urlParts = id.split('.');
    const mitreUrl = urlParts.length > 1 
      ? `https://attack.mitre.org/techniques/${urlParts[0]}/${urlParts[1]}/` 
      : `https://attack.mitre.org/techniques/${urlParts[0]}/`;

    return `<li>
              <a href="${mitreUrl}" target="_blank" rel="noopener noreferrer">
                <strong>${escapeHTML(id)}</strong>
              </a>${name}
            </li>`;
  };

  const core = (data.core || []).map(renderItem).join("");
  const related = (data.related || []).map(renderItem).join("");

  return (core || related) 
    ? `<div class="info-block mitre"><h4>Tecniche MITRE</h4><ul>${core}${related}</ul></div>` 
    : null;
}

function buildCveBlock(predicate) {
  const data = cve[predicate];
  if (!data || !data.cve?.length) return null;
  const listHtml = data.cve.map(id => `<li><a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank">${id}</a> ${kevList.includes(id) ? '<span class="badge-kev">Active Exploit</span>' : ''}</li>`).join("");
  return `<div class="info-block cve"><h4>CVE Correlate</h4><ul>${listHtml}</ul></div>`;
}

function buildKillChainBlock(predicate) {
  const phase = killchain[predicate];
  return (phase && phase !== "None") ? `<div class="info-block killchain"><h4>Kill Chain Phase</h4><p>${phase}</p></div>` : null;
}

function escapeHTML(str) {
  if (!str) return "";
  return String(str).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]));
}