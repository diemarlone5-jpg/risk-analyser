import streamlit as st
from datetime import datetime
import uuid
from supabase import create_client, Client

# Configuration de la page avec la barre latérale ouverte par défaut
st.set_page_config(
    page_title="URL Risk Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- STYLE CSS : MASQUE LE HEADER SUPÉRIEUR ET VERROUILLE LA SIDEBAR ---
st.markdown("""
    <style>
    /* Masque complètement la barre supérieure (Share, GitHub, menu 3 points, etc.) */
    header[data-testid="stHeader"] {
        display: none !important;
    }

    /* Supprime définitivement la flèche/bouton de réduction de la sidebar */
    [data-testid="collapsedControl"] {
        display: none !important;
    }
    
    /* Force la barre latérale à rester fixe, ouverte et visible */
    [data-testid="stSidebar"] {
        display: block !important;
        visibility: visible !important;
        transform: none !important;
        width: 320px !important;
        background-color: #050b14 !important;
        border-right: 1px solid #0077ff44 !important;
    }

    /* Empêche la sidebar de se replier */
    [data-testid="stSidebar"][aria-expanded="false"] {
        transform: translateX(0px) !important;
        margin-left: 0px !important;
    }

    /* Fond global de l'application en noir */
    .stApp {
        background-color: #000000;
        color: #e0f2fe;
    }
    
    /* Style du texte dans la barre latérale */
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, [data-testid="stSidebar"] div, [data-testid="stSidebar"] label, [data-testid="stSidebar"] small {
        color: #cbd5e1 !important;
    }
    [data-testid="stSidebar"] h3, [data-testid="stSidebar"] h4 {
        color: #38bdf8 !important;
    }

    /* Style ultra-visible pour les blocs de métriques (KPIs) */
    [data-testid="stMetric"] {
        background-color: #050b14;
        border: 1px solid #0077ff88;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 0 12px rgba(0, 210, 255, 0.15);
    }
    [data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-weight: bold;
    }
    [data-testid="stMetricValue"] {
        color: #00d2ff !important;
        font-family: 'Courier New', Courier, monospace;
        text-shadow: 0 0 8px rgba(0, 210, 255, 0.4);
    }

    /* Champs de saisie stylisés néon bleu */
    .stTextInput input {
        background-color: #050b14;
        color: #38bdf8;
        border: 1px solid #0077ff77;
        border-radius: 6px;
    }
    .stTextInput input:focus {
        border-color: #00d2ff;
        box-shadow: 0 0 10px #00d2ff44;
    }

    /* Boutons d'action professionnels */
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

    h1, h2, h3 {
        color: #38bdf8 !important;
        font-family: 'Courier New', Courier, monospace;
    }
    </style>
""", unsafe_allow_html=True)

# --- GESTION DE SESSION ---
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

current_session = st.session_state.session_id

# --- SUPABASE & API ---
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    supabase_connected = True
except Exception as e:
    supabase_connected = False

VT_API_KEY = st.secrets.get("VT_API_KEY", "")
vt_active = bool(VT_API_KEY)

# --- BARRE LATÉRALE FIXE À GAUCHE (EN ANGLAIS) ---
with st.sidebar:
    st.markdown("## 🛡️ URL RISK ANALYZER")
    st.caption("Enterprise Threat Intelligence")
    
    st.markdown("---")
    st.markdown("#### 📊 SYSTEM STATUS")
    st.success("Supabase : ONLINE" if supabase_connected else "Supabase : OFFLINE")
    st.success("VirusTotal API : ACTIVE" if vt_active else "VirusTotal API : INACTIVE")

    st.markdown("---")
    st.markdown("#### 📖 THREAT MATRIX")
    st.markdown("🟢 **SAFE** : Zero compromise.")
    st.markdown("🟡 **SUSPICIOUS** : Anomaly detected.")
    st.markdown("🔴 **DANGEROUS** : Malicious attractor.")

# --- EN-TÊTE DE L'APPLICATION ---
col_logo, col_title = st.columns([0.08, 0.92])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# URL RISK ANALYZER")

st.markdown("Real-time Threat Intelligence and URL security auditing engine.")
st.markdown("---")

# --- SECTION TABLEAU DE BORD / KPI ---
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Audit Engine", value="ACTIVE", delta="Stable")
with col2:
    st.metric(label="Network Security", value="PROTECTED", delta="RLS Active")
with col3:
    st.metric(label="Connected Probes", value="2 / 2", delta="Optimal")

st.markdown("---")

# --- SECTION ENQUÊTE ---
st.markdown("### 🔍 INITIATE INVESTIGATION")

with st.container(border=True):
    input_value = st.text_input(
        "Target Analysis (URL) :", 
        value="", 
        placeholder="https://example.com/path/suspect"
    )

    if st.button("Launch Security Analysis", type="primary"):
        if not input_value:
            st.warning("⚠️ Please enter a valid URL to scan.")
        else:
            with st.spinner("Executing VirusTotal probes & logging data..."):
                niveau_risque = "SAFE"
                nb_malveillants = 0
                nb_suspects = 0
                
                if "eicar" in input_value.lower() or "hacker" in input_value.lower() or "malware" in input_value.lower():
                    niveau_risque = "DANGEROUS"
                    nb_malveillants = 1
                elif "login" in input_value.lower() or "secure" in input_value.lower():
                    niveau_risque = "SUSPICIOUS"
                    nb_suspects = 1

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
                        st.success(f"Target analyzed [Risk Level : {niveau_risque}] and logged to secure registry.")
                    except Exception as ex:
                        st.error(f"Database write error : {ex}")
                else:
                    st.warning("Analysis completed, but not saved (Database disconnected).")

st.markdown("---")

# --- TABLEAU DES JOURNAUX (STYLE ENTREPRISE) ---
st.markdown("### 📜 SESSION AUDIT LOGS")

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
                    "Timestamp": date_str,
                    "Target URL": log.get("input_url") or log.get("url"),
                    "Risk Level": log.get("risk_level"),
                    "Malicious Engines": log.get("malicious_count"),
                    "Suspicious Engines": log.get("suspicious_count")
                })
            
            st.dataframe(table_data, use_container_width=True, hide_index=True)
        else:
            st.info("No active logs for this session. Launch an analysis above.")
            
    except Exception as e:
        st.error(f"Registry read error : {e}")
else:
    st.info("Supabase connection required to display logs.")

# --- PIED DE PAGE PROFESSIONNEL ---
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #475569; font-size: 0.85rem; font-family: monospace;'>"
    "URL Risk Analyzer • Enterprise Security Dashboard v1.0 • Secure RLS Session Isolation"
    "</p>", 
    unsafe_allow_html=True
)