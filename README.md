# 🛡️ Cyber Taxonomy Viewer (ACN, MITRE & ISO Framework)

Un'applicazione web interattiva progettata per la classificazione, l'analisi e la mitigazione degli incidenti cyber, basata sulla tassonomia ufficiale dell'**Agenzia per la Cybersicurezza Nazionale (ACN)**.



## 🎯 Finalità del Progetto
Il tool è stato sviluppato per trasformare dati tassonomici statici in uno strumento operativo di **Threat Intelligence** e **Governance**. Permette di:
* **Uniformare il Reporting:** Fornire i tag corretti `acn:predicate="value"` per le comunicazioni ufficiali.
* **Analisi Multi-Framework:** Correlare ogni minaccia alle tecniche **MITRE ATT&CK**, alle **CVE** e ai controlli **ISO 27001**.
* **Visualizzare il Percorso d'Attacco:** Comprendere visivamente come un vettore (es. Email) si trasforma in un impatto (es. Data Leak) attraverso la Kill Chain.
* **Supporto Decisionale:** Generare istantaneamente Cheat-Sheet per i team di Incident Response.

---

## 🏗️ Struttura dei File

### Frontend (Core)
* `index.html`: Struttura portante con barra di ricerca globale e supporto per la visualizzazione a matrice.
* `style.css`: Design di sistema (Modern Dark/Light UI) con animazioni per il "percorso critico" e badge di allerta.
* `app.js`: Motore logico in puro JavaScript (ES6). Gestisce il filtraggio dei dati, l'inferenza delle relazioni e la gestione della memoria cache.

### Dataset (JSON)
* `machinetag.json`: Tassonomia ACN originale.
* `acn_enriched.json`: Mappatura delle macro-categorie (Baseline, Threat Type, ecc.).
* `mitre_mapping_enriched.json`: Database delle tecniche MITRE correlate con ID e descrizioni.
* `cve_mapping.json`: Correlazione dinamica con vulnerabilità note.
* `cisa_kev_list.json`: Elenco delle vulnerabilità con exploit attivo nel mondo reale.
* `killchain_mapping.json`: Distribuzione dei predicati nelle fasi della Cyber Kill Chain.

---

## 🚀 Funzionalità Avanzate

### 1. 📊 Matrice delle Relazioni (Attack Path)
La vista "Matrice" permette di cliccare su un qualsiasi nodo (Vettore, Minaccia o Impatto) per visualizzare l'intera catena cinematica dell'attacco. Il sistema evidenzia automaticamente:
- **Punto di Origine** (Vettore)
- **Metodo di Esecuzione** (Minaccia)
- **Fase Temporale** (Kill Chain)
- **Conseguenza Finale** (Impatto)
- **Contromisura** (Controllo ISO 27001)



### 2. 📋 Incident Cheat-Sheet Generator
Sotto ogni voce della tassonomia, il tasto **"Genera Cheat-Sheet"** crea un documento di pronto intervento che include:
* **Tagging Tecnico:** Codifica esatta per il database degli incidenti.
* **Focus Detection:** Quali TTPs (Tecniche MITRE) monitorare per rilevare l'attività.
* **Compliance Check:** Quali controlli ISO 27001 verificare per assicurare che la mitigazione sia attiva.

### 3. 🔍 Ricerca Globale "Deep Search"
La barra di ricerca superiore esegue una scansione trasversale su tutti i file JSON, permettendo di trovare una minaccia partendo anche solo da un frammento di descrizione o da un codice CVE.

---

## 🛠️ Installazione e Aggiornamento
1.  **Deployment:** Caricare tutti i file in una directory del server web (o aprire localmente).
2.  **Aggiornamento Dati:** Eseguire periodicamente lo script `update_mappings.py` per sincronizzare i nomi delle tecniche MITRE e l'elenco CISA KEV (vulnerabilità sfruttate).

---

## 🏷️ Standard Utilizzati
* **ACN T-01:** Tassonomia nazionale degli incidenti.
* **MITRE ATT&CK v14+**: Framework delle tattiche e tecniche.
* **NVD & CISA KEV**: Database delle vulnerabilità.
* **ISO/IEC 27001:2022 Annex A**: Controlli di sicurezza dell'informazione.

---
*Sviluppato come strumento di supporto tattico per la protezione delle infrastrutture critiche.*
