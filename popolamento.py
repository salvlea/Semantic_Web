from owlready2 import *
import random
# --- CONFIGURAZIONE ---
# Nome del file OWL che hai salvato da Protégé
input_file = "Untitled.rdf"
# Nome del file che verrà creato
output_file = "cyberseconto_populated.owl"
# IL TUO IRI (Copialo da Protégé esattamente, compreso il # finale se c'è, o aggiungilo)
# Se in Protégé è http://www.semanticweb.org/salvleanza/ontologies/cybersOnto
# Qui metti:
base_iri = "http://www.semanticweb.org/salvleanza/ontologies/cybersOnto#"

# --- CARICAMENTO ---
onto_path.append(".")
try:
    onto = get_ontology(input_file).load()
    print("✅ Ontologia caricata!")
except:
    print(f"❌ Errore: Non trovo '{input_file}'.")
    exit()

with onto:
    print("  Generazione dati in corso...")

    # 1. CREIAMO LE VULNERABILITÀ
    vulns = []
    for i in range(1, 11): # 10 Vulnerabilità
        v_name = f"CVE_2025_{1000+i}"
        # Creiamo l'individuo della classe Vulnerability
        new_v = onto.Vulnerability(v_name)
        
        # Assegniamo CVSS a caso (alcuni > 8 per testare la regola Critical)
        score = round(random.uniform(4.0, 10.0), 1)
        new_v.hasCVSSScore.append(score)
        
        vulns.append(new_v)
        print(f"  -> Vuln: {v_name} (Score: {score})")

    # 2. CREIAMO GLI ATTACCHI (Per la nuova regola Attack)
    attacks = []
    attack_names = ["WannaCry", "Log4Shell_Exploit", "Phishing_Campaign", "DDoS_Botnet"]
    
    for i, name in enumerate(attack_names):
        # Istanziamo la classe Attack
        # Nota: in Python usiamo il nome della classe come appare nell'OWL
        new_attack = onto.Attack(f"{name}_{i}")
        
        # L'attacco sfrutta una vulnerabilità a caso
        target_vuln = random.choice(vulns)
        new_attack.exploits.append(target_vuln)
        
        attacks.append(new_attack)
        print(f"  -> Attack: {new_attack.name} exploits {target_vuln.name}")

    # 3. CREIAMO I SISTEMI
    for i in range(1, 21): # 20 Sistemi
        s_name = f"Server_Production_{i}"
        new_sys = onto.Server(s_name)
        
        # Assegniamo una vulnerabilità a caso
        # (Se becchiamo quella sfruttata dall'attacco, scatterà PotentiallyAttackable)
        my_vuln = random.choice(vulns)
        new_sys.hasVulnerability.append(my_vuln)
        
        # Transitività (opzionale, per fare scena)
        if i > 1 and i < 5:
             prev_sys = onto.search_one(iri = f"*{base_iri}Server_Production_{i-1}")
             if prev_sys:
                 new_sys.dependsOn.append(prev_sys)

    print("✅ Popolamento completato.")
    onto.save(file=output_file)
    print(f" File salvato come '{output_file}'.")