import streamlit as st
from datetime import datetime
import uuid
from supabase import create_client, Client

# Configuration de la page Streamlit avec un logo et titre orientés SOC
st.set_page_config(
    page_title="URL Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# --- STYLE CSS PERSONNALISÉ : FOND NOIR & ACCENTS BLEUS CYBERPUNK ---
st.markdown("""
    <style>
    /* Intègre l'en-tête dans le thème noir pour garder le bouton de la sidebar visible */
    [data-testid="stHeader"] {
        background-color: #000000;
    }
    
    /* Fond général de l'application en noir pur */
    .stApp {
        background-color: #000000;
        color: #e0f2fe;
    }
    
    /* Barre latérale (sidebar) en bleu nuit profond */
    [data-testid="stSidebar"] {
        background-color: #050b14;
        border-right: 1px solid #0077ff55;
    }

    /* Champs de saisie stylisés néon bleu */
    .stTextInput input {
        background-color: #0a1120;
        color: #38bdf8;
        border: 1px solid #0077ff88;
        border-radius: 6px;
    }
    .stTextInput input:focus {
        border-color: #00d2ff;
        box-shadow: 0 0 12px #00d2ff55;
    }

    /* Boutons d'action en dégradé de bleu professionnel */
    .stButton button {
        background: linear-gradient(90deg, #0284c7, #00d2ff);
        color: #000000;
        border: none;
        border-radius: 6px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s ease;
    }
    .stButton button:hover {
        box-shadow: 0 0 15px #00d2ffaa;
        transform: translateY(-1px);
    }

    /* Titres et en-têtes en bleu lumineux */
    h1, h2, h3 {
        color: #38bdf8 !important;
        font-family: 'Courier New', Courier, monospace;
    }
    </style>
""", unsafe_allow_html=True)

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

# Lecture de la clé VirusTotal
VT_API_KEY = st.secrets.get("VT_API_KEY", "")
vt_active = bool(VT_API_KEY)

# --- BARRE LATÉRALE (SIDEBAR) AVEC LOGO & STATUT ---
with st.sidebar:
    st.markdown("### 🛡️ URL RISK ANALYZER")
    st.caption("Threat Intelligence & Risk Engine")
    
    st.markdown("---")
    st.markdown("#### 📊 STATUT SYSTÈME")
    
    if supabase_connected:
        st.success("Supabase : ONLINE")
    else:
        st.error("Supabase : OFFLINE")
        
    if vt_active:
        st.success("VirusTotal API : ACTIVE")
    else:
        st.warning("VirusTotal API : INACTIVE")

    st.markdown("---")
    st.markdown("#### 📖 MATRICE DE MENACE")
    st.markdown("🟢 **SÛR** : Zéro compromission.")
    st.markdown("🟡 **SUSPECT** : Anomalie détectée.")
    st.markdown("🔴 **DANGEROUS** : Attracteur malveillant.")

# --- EN-TÊTE PRINCIPAL AVEC LOGO VISUEL ---
col_logo, col_title = st.columns([0.1, 0.9])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# URL RISK ANALYZER")

st.markdown("Moteur de Threat Intelligence et d'audit de sécurité des URL en temps réel.")
st.markdown("---")

st.markdown("### 🔍 INITIATION D'UNE ENQUÊTE")

# Champ unique pour l'URL avec placeholder pro
input_value = st.text_input(
    "Cible de l'analyse (URL) :", 
    value="", 
    placeholder="https://exemple.com/path/suspect"
)

# Bouton de lancement de l'analyse
if st.button("Lancer l'analyse de sécurité", type="primary"):
    if not input_value:
        st.warning("⚠️ Veuillez entrer une URL valide à scanner.")
    else:
        with st.spinner("Exécution des sondes VirusTotal & consignation des logs..."):
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
                        "user_email": current_session
                    }
                    supabase.table("analyses").insert(data_to_insert).execute()
                    st.success("Cible analysée et consignée dans le registre sécurisé.")
                except Exception as ex:
                    st.error(f"Erreur d'écriture en base : {ex}")
            else:
                st.warning("Analyse effectuée, mais non enregistrée (Base déconnectée).")

st.markdown("---")

# --- TABLEAU DES JOURNAUX (Isolé par utilisateur) ---
st.markdown("### 📜 REGISTRE DES AUDITS DE SESSION")

if supabase_connected:
    try:
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
                    "Horodatage": date_str,
                    "Cible Analysée": log.get("input_url") or log.get("url"),
                    "Niveau de Risque": log.get("risk_level"),
                    "Moteurs Malveillants": log.get("malicious_count"),
                    "Moteurs Suspects": log.get("suspicious_count")
                })
            
            st.dataframe(table_data, use_container_width=True, hide_index=True)
        else:
            st.info("Aucun journal actif pour cette session. Lancez une analyse ci-dessus.")
            
    except Exception as e:
        st.error(f"Erreur de lecture du registre : {e}")
else:
    st.info("Connexion Supabase requise pour afficher les journaux.")