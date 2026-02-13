import json
import requests

def update_data():
    # 1. Carica il tuo machinetag.json per avere la lista dei predicati
    with open('machinetag.json', 'r') as f:
        machinetag = json.load(f)
    predicates = [p['value'] for p in machinetag['predicates']]

    # 2. Scarica CISA KEV (vulnerabilità note e sfruttate)
    print("Recupero dati CISA KEV...")
    kev_data = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()
    vulnerabilities = kev_data['vulnerabilities']

    # 3. Aggiorna cve_mapping.json
    # Logica: se una CVE nel KEV contiene nel nome o descrizione il valore del predicato
    new_cve_mapping = {}
    for pred in predicates:
        # Cerchiamo match intelligenti nelle descrizioni delle vulnerabilità
        matches = [
            v['cveID'] for v in vulnerabilities 
            if pred.replace('-', ' ') in v['shortDescription'].lower() 
            or pred.replace('-', '') in v['shortDescription'].lower()
        ]
        # Teniamo solo le ultime 10 più recenti per ogni predicato
        new_cve_mapping[pred] = {"cve": matches[:10]}

    with open('cve_mapping.json', 'w') as f:
        json.dump(new_cve_mapping, f, indent=2)
    print("cve_mapping.json aggiornato.")

    # 4. Aggiorna mitre_mapping.json (Opzionale: scarica definizioni tecniche)
    # Qui potresti scaricare il database STIX del MITRE per arricchire i nomi delle tecniche
    # Per ora manteniamo la tua struttura aggiungendo eventuali nuove tecniche scoperte
    # (Logica simile a quella sopra ma sui feed MITRE)

if __name__ == "__main__":
    update_data()