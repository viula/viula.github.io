import json
import requests

def update():
    print("Avvio arricchimento dati...")
    
    # 1. Scarica MITRE ATT&CK (per nomi tecniche)
    print("Recupero nomi tecniche MITRE...")
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mitre_raw = requests.get(mitre_url).json()
    mitre_db = {obj['external_references'][0]['external_id']: obj['name'] 
                for obj in mitre_raw['objects'] 
                if obj.get('type') == 'attack-pattern' and obj.get('external_references')}

    # 2. Scarica CISA KEV (per priorità e mapping CVE)
    print("Recupero catalogo CISA KEV...")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_raw = requests.get(kev_url).json()
    vulnerabilities = kev_raw['vulnerabilities']
    kev_ids = [v['cveID'] for v in vulnerabilities]

    # 3. Carica i file locali del tuo progetto
    with open('machinetag.json', 'r') as f:
        machinetag = json.load(f)
    with open('mitre_mapping.json', 'r') as f:
        mitre_map = json.load(f)

    # 4. Generazione automatica cve_mapping.json
    # Cerchiamo match tra predicati ACN e descrizioni CVE nel catalogo KEV
    new_cve_mapping = {}
    all_predicates = [p['value'] for p in machinetag['predicates']]
    
    for pred in all_predicates:
        search_term = pred.replace('-', ' ').lower()
        matches = [
            v['cveID'] for v in vulnerabilities 
            if search_term in v['shortDescription'].lower()
        ]
        new_cve_mapping[pred] = {"cve": matches[:10]} # Limitiamo a 10 per predicato

    # 5. Arricchimento MITRE: aggiungiamo i nomi alle tecniche
    enriched_mitre = {}
    for pred, data in mitre_map.items():
        enriched_mitre[pred] = {
            "core": [{"id": tid, "name": mitre_db.get(tid, "Unknown")} for tid in data.get('core', [])],
            "related": [{"id": tid, "name": mitre_db.get(tid, "Unknown")} for tid in data.get('related', [])]
        }

    # 6. Salvataggio di tutti i file necessari al frontend
    with open('cve_mapping.json', 'w') as f:
        json.dump(new_cve_mapping, f, indent=2)
        
    with open('mitre_mapping_enriched.json', 'w') as f:
        json.dump(enriched_mitre, f, indent=2)
        
    with open('cisa_kev_list.json', 'w') as f:
        json.dump(kev_ids, f)

    print(f"Successo! Mappate {len(kev_ids)} CVE critiche e arricchiti i predicati MITRE.")

if __name__ == "__main__":
    update()