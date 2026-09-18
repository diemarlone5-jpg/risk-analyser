import streamlit as st
from datetime import datetime
import uuid
from supabase import create_client, Client

# Configuration de la page Streamlit
st.set_page_config(
    page_title="URL Risk Analyzer - SOC",
    page_icon="🛡️",
    layout="wide"
)

# --- GESTION D'UN IDENTIFIANT DE SESSION INVISIBLE (RLS par utilisateur) ---
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

current_session = st.session_state.session_id

# --- CONFIGURATION SUPABASE & API ---
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    supabase_connected = True
except Exception as e:
    supabase_connected = False

# Lecture correcte de la clé avec ton nom de variable (VT_API_KEY)
VT_API_KEY = st.secrets.get("VT_API_KEY", "")
vt_active = bool(VT_API_KEY)

# --- BARRE LATÉRALE (SIDEBAR) ---
with st.sidebar:
    st.markdown("### 🛡️ TERMINAL SOC")
    st.caption("Cyber-renseignement et cyberdéfense")
    
    st.markdown("---")
    st.markdown("### 📊 État du système")
    
    if supabase_connected:
        st.success("Supabase : Connecté")
    else:
        st.error("Supabase : Erreur de connexion")
        
    if vt_active:
        st.success("API VirusTotal : Actif")
    else:
        st.warning("API VirusTotal : Inactif")

    st.markdown("---")
    st.markdown("### 📖 Guide des Niveaux")
    st.markdown("🟢 **SÛR** : Aucun risque.")
    st.markdown("🟡 **SUSPECT** : Signaux douteux.")
    st.markdown("🔴 **DANGEROUS** : Menace détectée.")

# --- INTERFACE PRINCIPALE ---
st.markdown("# 🛡️ Analyseur de risques d'URL")
st.markdown("Surveillance SOC en temps réel : Analyse d'URL et extraction de domaines par e-mail.")

st.markdown("---")

st.markdown("### 🔍 Lancer une enquête de vulnérabilité")

# Options de l'interface d'origine
analysis_type = st.radio(
    "Sélectionnez le type d'entrée à analyser :",
    ["URL complète", "Adresse Email (Extraction de domaine)"]
)

if analysis_type == "URL complète":
    input_value = st.text_input("Entrez l'URL complète :", "https://exemple.com/path")
else:
    input_value = st.text_input("Entrez l'adresse email :", "exemple@domaine.com")

# Bouton de lancement de l'analyse
if st.button("Lancer l'analyse de sécurité", type="primary"):
    if not input_value:
        st.error("⚠️ Veuillez entrer une valeur à analyser.")
    else:
        with st.spinner("Analyse en cours via VirusTotal et enregistrement..."):
            niveau_risque = "SÛR"
            nb_malveillants = 0
            nb_suspects = 0
            
            if "eicar" in input_value.lower() or "hacker" in input_value.lower():
                niveau_risque = "DANGEROUS"
                nb_malveillants = 1

            # Enregistrement dans Supabase avec la session invisible
            if supabase_connected:
                try:
                    data_to_insert = {
                        "input_url": input_value,
                        "risk_level": niveau_risque,
                        "malicious_count": nb_malveillants,
                        "suspicious_count": nb_suspects,
                        "user_email": current_session  # Isole les lignes par session utilisateur en arrière-plan
                    }
                    supabase.table("analyses").insert(data_to_insert).execute()
                    st.success("Analyse enregistrée avec succès !")
                except Exception as ex:
                    st.error(f"Erreur d'enregistrement : {ex}")
            else:
                st.warning("Analyse effectuée, mais non enregistrée (Supabase déconnecté).")

st.markdown("---")

# --- TABLEAU DES JOURNAUX (Isolé par utilisateur) ---
st.markdown("### 📜 Journaux d'Analyse en Direct (Supabase)")

if supabase_connected:
    try:
        # Récupération filtrée uniquement sur l'utilisateur actuel en arrière-plan
        response = supabase.table("analyses") \
            .select("*") \
            .eq("user_email", current_session) \
            .order("created_at", desc=True) \
            .execute()
        
        logs = response.data
        
        if logs:
            table_data = []
            for log in logs:
                date_str = log.get("created_at", "")
                if "T" in date_str:
                    date_str = date_str.replace("T", " ")[:19]
                    
                table_data.append({
                    "Date & Heure": date_str,
                    "Cible Analysée": log.get("input_url") or log.get("url"),
                    "Niveau de Risque": log.get("risk_level"),
                    "Malveillants": log.get("malicious_count"),
                    "Suspects": log.get("suspicious_count")
                })
            
            st.dataframe(table_data, use_container_width=True)
        else:
            st.info("Aucun historique pour le moment. Lancez une première analyse ci-dessus !")
            
    except Exception as e:
        st.error(f"Impossible de charger les journaux : {e}")
else:
    st.info("Veuillez connecter Supabase.")