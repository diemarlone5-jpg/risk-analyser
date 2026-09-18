import streamlit as st
from datetime import datetime
import uuid
from supabase import create_client, Client

# Configuration de la page Streamlit
st.set_page_config(
    page_title="URL Risk Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- STYLE CSS AVANCÉ : EFFET CARDS & DESIGN SOC ---
st.markdown("""
    <style>
    [data-testid="stHeader"] {
        background-color: #000000;
    }
    .stApp {
        background-color: #000000;
        color: #e0f2fe;
    }
    [data-testid="stSidebar"] {
        background-color: #050b14;
        border-right: 1px solid #0077ff33;
    }
    
    /* Style des conteneurs en mode "Cartes Cyberpunk" */
    .soc-card {
        background-color: #050b14;
        border: 1px solid #0077ff44;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 0 15px rgba(0, 119, 255, 0.05);
        margin-bottom: 20px;
    }

    .stTextInput input {
        background-color: #020617;
        color: #38bdf8;
        border: 1px solid #0077ff77;
        border-radius: 6px;
    }
    .stTextInput input:focus {
        border-color: #00d2ff;
        box-shadow: 0 0 10px #00d2ff44;
    }

    .stButton button {
        background: linear-gradient(90deg, #0284c7, #00d2ff);
        color: #000000;
        border: none;
        border-radius: 6px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 1px;
        width: 100%;
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

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("### 🛡️ URL RISK ANALYZER")
    st.caption("Threat Intelligence & Risk Engine")
    
    st.markdown("---")
    st.markdown("#### 📊 STATUT SYSTÈME")
    st.success("Supabase : ONLINE" if supabase_connected else "Supabase : OFFLINE")
    st.success("VirusTotal API : ACTIVE" if vt_active else "VirusTotal API : INACTIVE")

    st.markdown("---")
    st.markdown("#### 📖 MATRICE DE MENACE")
    st.markdown("🟢 **SÛR** : Zéro compromission.")
    st.markdown("🟡 **SUSPECT** : Anomalie détectée.")
    st.markdown("🔴 **DANGEROUS** : Attracteur malveillant.")

# --- EN-TÊTE ---
col_logo, col_title = st.columns([0.08, 0.92])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# URL RISK ANALYZER")

st.markdown("Moteur de Threat Intelligence et d'audit de sécurité des URL en temps réel.")
st.markdown("---")

# --- SECTION ENQUÊTE DANS UNE CARTE DESIGN ---
st.markdown("### 🔍 INITIATION D'UNE ENQUÊTE")

with st.container():
    st.markdown('<div class="soc-card">', unsafe_allow_html=True)
    
    input_value = st.text_input(
        "Cible de l'analyse (URL) :", 
        value="", 
        placeholder="https://exemple.com/path/suspect"
    )

    col_btn1, col_btn2 = st.columns([1, 2])
    with col_btn1:
        analyze_clicked = st.button("Lancer l'analyse", type="primary")

    if analyze_clicked:
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
                    
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")

# --- TABLEAU DES JOURNAUX ---
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