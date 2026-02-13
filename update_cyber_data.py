import json
import requests

def update():
    # 1. Carica i predicati dal tuo machinetag.json
    with open('machinetag.json', 'r') as f:
        machinetag = json.load(f)
    
    # Estraiamo tutti i valori dei predicati e i valori dentro gli 'entries'
    all_terms = []
    for pred in machinetag['predicates']:
        all_terms.append(pred['value'])
        if 'entries' in pred:
            for entry in pred['entries']:
                all_terms.append(entry['value'])

    # 2. Scarica CISA KEV (Live Feed)
    print("Fetching CISA KEV data...")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_data = requests.get(kev_url).json()['vulnerabilities']

    # 3. Mappatura CVE
    new_cve_mapping = {}
    for term in all_terms:
        # Cerchiamo match: il termine deve apparire nella descrizione della CVE
        # Puliamo il termine (es. 'active-scanning' -> 'active scanning')
        search_term = term.replace('-', ' ').lower()
        
        matches = [
            v['cveID'] for v in kev_data 
            if search_term in v['shortDescription'].lower()
        ]
        # Teniamo solo le 10 più recenti per non appesantire il JSON
        new_cve_mapping[term] = {"cve": matches[:10]}

    # 4. Salvataggio
    with open('cve_mapping.json', 'w') as f:
        json.dump(new_cve_mapping, f, indent=2)
    
    print(f"Aggiornamento completato: {len(new_cve_mapping)} termini mappati.")

if __name__ == "__main__":
    update()