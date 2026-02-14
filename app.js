/* ============================================================
   ACN VIEWER - FINAL STABLE VERSION
============================================================ */

let acn = null;
let enriched = null;
let mitreEnriched = null; 
let cve = null;
let kevList = []; 
let killchain = null;

const ACN_RELATIONS = {
    // VETTORE -> MINACCE CORRELATE
    "email": ["social-engineering", "malicious-code"],
    "web": ["vulnerability", "malicious-code", "active-scanning"],
    "removable-media": ["malicious-code"],
    "external-assets": ["vulnerability", "availability", "data-exposure"],
    
    // MINACCIA -> IMPATTI TIPICI
    "malicious-code": ["infection", "data-exfiltration", "service-disruption"],
    "social-engineering": ["unauthorised-access", "fraud"],
    "availability": ["service-disruption", "system-crash"],
    "vulnerability": ["unauthorised-access", "data-leak"]
};

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
    setupSearch();
    
  } catch (error) {
    console.error("Errore nel caricamento:", error);
  }
}

loadData();

/* --- TABS --- */
function buildMacroTabs() {
  const tabs = document.getElementById("macroTabs");
  tabs.innerHTML = ""; // Pulisce il contenitore

  // 1. Crea le tab standard (BC, TT, TA, AC)
  const order = ["BC", "TT", "TA", "AC"];
  order.forEach(code => {
    const macro = enriched.macro_categories[code];
    if (!macro) return;
    const btn = document.createElement("button");
    btn.className = "macro-tab";
    btn.dataset.macro = code;
    btn.textContent = `${code} — ${macro.name}`;
    btn.addEventListener("click", () => {
        // Nasconde la matrice se l'utente torna sulle tab normali
        document.getElementById("matrixView").style.display = "none";
        document.getElementById("tabContent").style.display = "block";
        selectMacroTab(code);
    });
    tabs.appendChild(btn);
  });

  // 2. AGGIUNGI ORA IL PULSANTE SPECIALE (così non sparisce più)
  const specialBtn = document.createElement("button");
  specialBtn.className = "macro-tab special";
  specialBtn.innerHTML = "📊 Matrice Relazioni";
  specialBtn.onclick = () => {
      // De-seleziona le altre tab
      document.querySelectorAll(".macro-tab").forEach(b => b.setAttribute("aria-selected", "false"));
      specialBtn.setAttribute("aria-selected", "true");
      showRelationMatrix();
  };
  tabs.appendChild(specialBtn);
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

function setupSearch() {
  const searchInput = document.getElementById("globalSearch");
  
  searchInput.addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    const container = document.getElementById("tabContent");
    
    if (term.length < 2) {
      // Se la ricerca è vuota, ripristina la tab corrente
      const activeTab = document.querySelector(".macro-tab[aria-selected='true']");
      selectMacroTab(activeTab.dataset.macro);
      return;
    }

    // Ricerca globale in tutti i dati
    container.innerHTML = "";
    
    acn.predicates.forEach(pred => {
      const subset = acn.values.find(v => v.predicate === pred.value);
      const entries = subset?.entry || [];
      
      // Controlliamo se il termine è nel nome del predicato o nei suoi valori
      const matchInPred = pred.expanded.toLowerCase().includes(term) || pred.value.toLowerCase().includes(term);
      const matchingEntries = entries.filter(e => 
        e.expanded.toLowerCase().includes(term) || 
        e.description.toLowerCase().includes(term) ||
        e.value.toLowerCase().includes(term)
      );

      if (matchInPred || matchingEntries.length > 0) {
        const section = buildPredicateSection(pred);
        container.appendChild(section);
        
        // Se ci sono match specifici nei valori, apriamo l'accordion e renderizziamo
        if (term.length > 2) {
          const header = section.querySelector(".pred-header");
          const panel = section.querySelector(".pred-panel");
          togglePredicate(header, true);
          renderPredicatePanel(pred, panel, subset);
          panel.dataset.rendered = "true";
        }
      }
    });

    if (container.innerHTML === "") {
      container.innerHTML = `<div style="padding:40px; text-align:center; color:var(--muted);">Nessun risultato trovato per "${escapeHTML(term)}"</div>`;
    }
  });
}

function showRelationMatrix() {
  const tabContent = document.getElementById("tabContent");
  const matrixView = document.getElementById("matrixView");

  // Nascondi il contenuto standard e mostra la matrice
  tabContent.style.display = "none";
  matrixView.style.display = "block";

  matrixView.innerHTML = `
    <h2 style="color:white; margin-bottom:20px;">Mappa delle Relazioni ACN</h2>
    <div style="display: flex; justify-content: space-between; gap: 20px;">
      <div class="node-column" id="col-vectors"><h4>Vettori</h4></div>
      <div class="node-column" id="col-threats"><h4>Minacce</h4></div>
      <div class="node-column" id="col-killchain"><h4>Fase Kill Chain</h4></div>
      <div class="node-column" id="col-impact"><h4>Impatto Finali</h4></div>
    </div>
  `;

  // 1. Popola Vettori (dal predicato 'vector')
  const vectorEntries = acn.values.find(v => v.predicate === 'vector')?.entry || [];
  renderNodes('col-vectors', vectorEntries, '#3b82f6');

  // 2. Popola Minacce (tutti i predicati della macro TT)
  const ttPredicates = enriched.macro_categories['TT'].predicates;
  const threatNodes = acn.predicates.filter(p => ttPredicates.includes(p.value));
  renderNodes('col-threats', threatNodes, '#8b5cf6');

  // 3. Popola fasi Kill Chain uniche
  const phases = [...new Set(Object.values(killchain))].filter(p => p !== "None");
  renderNodes('col-killchain', phases.map(p => ({expanded: p})), '#10b981');

  // 4. Popola Impatti (macro BC)
  const bcPredicates = enriched.macro_categories['BC'].predicates;
  const impactNodes = acn.predicates.filter(p => bcPredicates.includes(p.value));
  renderNodes('col-impact', impactNodes, '#ef4444');
}

function renderNodes(columnId, items, color, predicateValue = null) {
  const col = document.getElementById(columnId);
  items.forEach(item => {
    const div = document.createElement("div");
    div.className = "relation-node";
    div.style.borderLeft = `4px solid ${color}`;
    
    // Salviamo i metadati nel DOM per poterli filtrare dopo
    const val = item.value || item.expanded.toLowerCase().replace(/\s+/g, '-');
    div.dataset.id = val;
    div.dataset.predicate = predicateValue || "";
    
    div.textContent = item.expanded;

    // EVENTI MOUSE
    div.onmouseenter = () => highlightConnections(val, predicateValue);
    div.onmouseleave = () => resetConnections();

    col.appendChild(div);
  });
}

function highlightConnections(id, predicate) {
    const allNodes = document.querySelectorAll('.relation-node');
    allNodes.forEach(n => {
        n.style.opacity = "0.1";
        n.classList.remove('step-1', 'step-2', 'step-3', 'step-4');
        const badge = n.querySelector('.step-badge');
        if (badge) badge.remove();
    });

    const steps = [];

    // FASE 1: Identifichiamo il punto di partenza
    const activeNode = document.querySelector(`.relation-node[data-id="${id}"]`);
    if (!activeNode) return;

    // Determiniamo se stiamo partendo da un Vettore o da una Minaccia
    let startType = "";
    if (predicate === 'vector') startType = "VEC";
    else if (enriched.macro_categories['TT'].predicates.includes(id)) startType = "THR";

    // COSTRUZIONE DEL PERCORSO
    if (startType === "VEC") {
        steps.push({id: id, label: "1. Origine"});
        const threats = ACN_RELATIONS[id] || [];
        if (threats.length > 0) {
            steps.push({id: threats[0], label: "2. Esecuzione"}); // Prendiamo la prima correlata
            const phase = killchain[threats[0]];
            if (phase) steps.push({id: phase.toLowerCase().replace(/\s+/g, '-'), label: "3. Fase KC"});
        }
    } else {
        steps.push({id: id, label: "1. Minaccia"});
        const phase = killchain[id];
        if (phase) steps.push({id: phase.toLowerCase().replace(/\s+/g, '-'), label: "2. Fase KC"});
        const impacts = ACN_RELATIONS[id] || [];
        if (impacts.length > 0) steps.push({id: impacts[0], label: "3. Impatto"});
    }

    // APPLICAZIONE VISIVA DEI PASSAGGI
    steps.forEach((step, index) => {
        const node = document.querySelector(`.relation-node[data-id="${step.id}"]`);
        if (node) {
            node.style.opacity = "1";
            node.style.borderColor = "var(--primary)";
            const badge = document.createElement('span');
            badge.className = 'step-badge';
            badge.textContent = step.label;
            node.appendChild(badge);
        }
    });
}

// Funzione di supporto per estrarre solo gli ID MITRE
function getMitreIds(id) {
    if (!mitreEnriched[id]) return [];
    const core = mitreEnriched[id].core || [];
    const related = mitreEnriched[id].related || [];
    // Gestisce sia se sono stringhe che oggetti
    return [...core, ...related].map(t => typeof t === 'string' ? t : t.id);
}

function resetConnections() {
  document.querySelectorAll('.relation-node').forEach(n => {
    n.style.opacity = "1";
    n.style.borderColor = "#334155"; // Colore bordo originale
  });
}
