import json
import requests
import gzip
import io

def update():
    # 1. Carica i tuoi file locali per conoscere la struttura
    with open('machinetag.json', 'r') as f:
        acn_data = json.load(f)
    
    # 2. Scarica CISA KEV (CVE attivamente sfruttate - Molto utile per il tuo tool)
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_list = requests.get(kev_url).json()['vulnerabilities']
    
    # 3. Logica di mapping (Esempio semplificato)
    # Creiamo un nuovo cve_mapping dinamico
    new_cve_mapping = {}
    
    for pred in acn_data['predicates']:
        pred_value = pred['value']
        # Cerchiamo nel KEV se ci sono CVE che hanno nel nome o descrizione il predicato
        # Nota: Qui puoi raffinare la logica di ricerca
        found_cves = [
            v['cveID'] for v in kev_list 
            if pred_value.replace('-', ' ') in v['shortDescription'].lower()
        ][:5] # Prendiamo le prime 5 per non appesantire
        
        new_cve_mapping[pred_value] = {"cve": found_cves}

    # 4. Salvataggio (sovrascrive i tuoi file che poi verranno caricati da app.js)
    with open('cve_mapping.json', 'w') as f:
        json.dump(new_cve_mapping, f, indent=2)

if __name__ == "__main__":
    update()