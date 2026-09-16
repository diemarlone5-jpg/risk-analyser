import os
import re
import requests
import streamlit as st
import validators
from dotenv import load_dotenv
from supabase import create_client, Client

# 1. Chargement des variables d'environnement
load_dotenv()

# Configuration Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL") or st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY") or st.secrets.get("SUPABASE_KEY")

# Configuration API VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or st.secrets.get("VIRUSTOTAL_API_KEY")

# Initialisation du client Supabase
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- FONCTIONS UTILES ---

def is_valid_url(url: str) -> bool:
    """Vérifie si la chaîne saisie a la structure d'une URL valide."""
    return validators.url(url) == True

def analyze_url_virustotal(url_to_check: str):
    """Envoie l'URL à l'API VirusTotal et analyse le JSON de réponse."""
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    
    # Étape A: Soumission de l'URL pour analyse
    data = {"url": url_to_check}
    response = requests.post(endpoint, headers=headers, data=data)
    
    if response.status_code != 200:
        return None, f"Erreur API ({response.status_code}): Impossible de soumettre l'URL."
    
    analysis_id = response.json()["data"]["id"]
    
    # Étape B: Récupération des résultats d'analyse
    report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report_response = requests.get(report_endpoint, headers=headers)
    
    if report_response.status_code != 200:
        return None, f"Erreur API ({report_response.status_code}): Impossible de lire le rapport."
    
    stats = report_response.json()["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    
    total = malicious + suspicious + harmless
    
    # Calcul d'un Risk Score (0 à 100)
    if total > 0:
        risk_score = min(int(((malicious * 2 + suspicious) / total) * 100) + (malicious * 10), 100)
    else:
        risk_score = 0

    # Détermination du niveau de risque
    if malicious > 0 or risk_score >= 50:
        risk_level = "DANGEROUS"
    elif suspicious > 0 or risk_score >= 20:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"
        
    reasons = []
    if malicious > 0:
        reasons.append(f"{malicious} moteur(s) de sécurité ont classé l'URL comme malveillante.")
    if suspicious > 0:
        reasons.append(f"{suspicious} moteur(s) de sécurité trouvent l'URL suspecte.")
    if risk_level == "SAFE":
        reasons.append("Aucun indicateur de menace détecté par les moteurs d'analyse.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons
    }, None

def save_to_supabase(url: str, risk_level: str, risk_score: int, reasons: list):
    """Enregistre l'analyse dans la table Supabase 'analyses'."""
    if not supabase:
        return False
    data = {
        "input_url": url,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": ", ".join(reasons)
    }
    supabase.table("analyses").insert(data).execute()
    return True

def get_history_from_supabase():
    """Consulte les analyses enregistrées précédemment."""
    if not supabase:
        return []
    response = supabase.table("analyses").select("*").order("created_at", desc=True).limit(10).execute()
    return response.data

# --- INTERFACE WEB (STREAMLIT) ---

st.set_page_config(page_title="URL Risk Analyzer", page_icon="🛡️")

st.title("🛡️ URL Risk Analyzer")
st.write("Saisissez un lien suspect pour obtenir une analyse de sécurité immédiate.")

# Formulaire de saisie
url_input = st.text_input("URL à analyser :", placeholder="https://example.com")

if st.button("Analyser l'URL"):
    if not url_input:
        st.warning("Veuillez saisir une URL.")
    elif not is_valid_url(url_input):
        st.error("❌ L'URL saisie n'est pas correctement formée (ex: doit commencer par http:// ou https://).")
    else:
        with st.spinner("Analyse auprès de l'API de sécurité en cours..."):
            result, error = analyze_url_virustotal(url_input)
            
            if error:
                st.error(error)
            else:
                # Affichage du résultat
                level = result["risk_level"]
                score = result["risk_score"]
                reasons = result["reasons"]
                
                if level == "SAFE":
                    st.success(f"Résultat : **{level}**")
                elif level == "SUSPICIOUS":
                    st.warning(f"Résultat : **{level}**")
                else:
                    st.error(f"Résultat : **{level}**")
                
                st.metric(label="Risk Score", value=f"{score}/100")
                
                st.write("**Raisons / Indicateurs :**")
                for r in reasons:
                    st.write(f"- {r}")
                
                # Sauvegarde Supabase
                saved = save_to_supabase(url_input, level, score, reasons)
                if saved:
                    st.toast("Analyse enregistrée dans Supabase !", icon="✅")

st.divider()

# Section Historique
st.subheader("📜 Historique des analyses récentes")
if st.button("Rafraîchir l'historique"):
    history = get_history_from_supabase()
    if history:
        st.dataframe(history)
    else:
        st.info("Aucune analyse enregistrée pour le moment.")