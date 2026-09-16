import streamlit as st
import pandas as pd
import requests
import base64
from supabase import create_client, Client

# --- 1. CONFIGURATION DE LA PAGE ---
st.set_page_config(
    page_title="URL Risk Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. INJECTION CSS CYBERPUNK (FOND NOIR & BLEU FLUOR) ---
st.markdown("""
    <style>
    /* Masquer les éléments Streamlit Cloud / Branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    [data-testid="stToolbar"] {display: none !important;}
    div[data-testid="stDecoration"] {display: none !important;}

    /* Fond noir global et texte lumineux */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }

    /* Barre latérale sombre */
    [data-testid="stSidebar"] {
        background-color: #030712;
        border-right: 1px solid #1e293b;
    }

    /* Titres en bleu fluor / cyan */
    h1, h2, h3 {
        color: #00f3ff !important;
        font-family: 'Courier New', Courier, monospace;
        letter-spacing: -0.5px;
    }

    /* Boutons personnalisés bleu fluor */
    .stButton>button {
        background: linear-gradient(135deg, #00f3ff 0%, #0072ff 100%);
        color: #030712;
        font-weight: bold;
        border: none;
        border-radius: 6px;
        padding: 0.6rem 1rem;
        box-shadow: 0 0 15px rgba(0, 243, 255, 0.4);
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        box-shadow: 0 0 25px rgba(0, 243, 255, 0.8);
        color: #ffffff;
    }

    /* Champs de saisie style terminal */
    .stTextInput>div>div>input {
        background-color: #111827;
        color: #00f3ff;
        border: 1px solid #1f2937;
        border-radius: 6px;
    }
    .stTextInput>div>div>input:focus {
        border-color: #00f3ff;
        box-shadow: 0 0 10px rgba(0, 243, 255, 0.3);
    }

    /* Tableaux */
    table {
        background-color: #0b0f19 !important;
        color: #e2e8f0 !important;
        border-collapse: collapse;
        width: 100%;
    }
    thead tr th {
        background-color: #111827 !important;
        color: #00f3ff !important;
        border-bottom: 2px solid #00f3ff !important;
        text-align: left;
        padding: 12px;
        font-family: 'Courier New', Courier, monospace;
    }
    tbody tr td {
        background-color: #0b0f19 !important;
        color: #e2e8f0 !important;
        border-bottom: 1px solid #1f2937 !important;
        padding: 12px;
    }

    [data-testid="stMetricValue"] {
        color: #00f3ff !important;
    }
    
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    </style>
""", unsafe_allow_html=True)

# --- 3. CONFIGURATION SÉCURISÉE SUPABASE & VIRUSTOTAL ---
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except Exception:
    SUPABASE_URL = "TON_SUPABASE_URL"
    SUPABASE_KEY = "TON_SUPABASE_ANON_KEY"
    VIRUSTOTAL_API_KEY = "TA_CLE_VIRUSTOTAL"

@st.cache_resource
def init_supabase():
    try:
        if SUPABASE_URL != "TON_SUPABASE_URL":
            return create_client(SUPABASE_URL, SUPABASE_KEY)
        return None
    except Exception:
        return None

supabase: Client = init_supabase()

# --- 4. BARRE LATÉRALE (SIDEBAR) ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-checked.png", width=70)
    st.header("Risk Analyzer")
    st.caption("Cyber Intelligence & Defense")
    
    st.markdown("---")
    st.subheader("État du système")
    
    if supabase:
        st.success("Supabase : Connecté")
    else:
        st.warning("Supabase : Hors-ligne")
        
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "TA_CLE_VIRUSTOTAL":
        st.success("VirusTotal API : Actif")
    else:
        st.error("VirusTotal API : Non configuré")
        
    st.markdown("---")
    st.subheader("Guide des Niveaux")
    st.markdown("""
    - 🟢 **SAFE** : Aucun risque.
    - 🟡 **SUSPICIOUS** : Signaux mineurs.
    - 🔴 **DANGEROUS** : Menace avérée.
    """)
    st.markdown("---")
    st.info("⚡ **Mode Présentation** : Sécurité maximale active.")

# --- 5. EN-TÊTE DE L'APPLICATION ---
st.title("🛡️ URL Risk Analyzer")
st.markdown("Surveillance en temps réel, analyse de menaces web et journalisation Supabase.")

st.markdown("---")

# --- 6. LOGIQUE D'ANALYSE ---
st.subheader("🔍 Lancer une enquête de vulnérabilité")
url_to_analyze = st.text_input("Entrez l'URL complète à analyser :", placeholder="https://exemple.com")
analyze_button = st.button("Lancer l'analyse de sécurité", type="primary", use_container_width=True)

if analyze_button and url_to_analyze:
    if VIRUSTOTAL_API_KEY == "TA_CLE_VIRUSTOTAL":
        st.error("⚠️ Veuillez configurer votre clé API VirusTotal.")
    else:
        with st.spinner("🔄 Interrogation des moteurs de cyber-menaces en cours..."):
            try:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                
                url_bytes = url_to_analyze.encode("utf-8")
                url_id = base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")
                report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(report_url, headers=headers)
                
                stats = {}
                api_success = False
                if response.status_code == 200:
                    attributes = response.json().get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    api_success = True
                
                if not api_success or not stats or all(v == 0 for v in stats.values()):
                    post_resp = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        data={"url": url_to_analyze},
                        headers=headers
                    )
                    if post_resp.status_code == 200:
                        analysis_id = post_resp.json()["data"]["id"]
                        analysis_report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        analysis_resp = requests.get(analysis_report_url, headers=headers)
                        if analysis_resp.status_code == 200:
                            stats = analysis_resp.json()["data"]["attributes"]["stats"]
                            api_success = True

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                if not api_success or (malicious == 0 and suspicious == 0 and harmless == 0 and undetected == 0):
                    risk_level = "DANGEROUS"
                    malicious = 1
                elif malicious > 0:
                    risk_level = "DANGEROUS"
                elif suspicious > 0:
                    risk_level = "SUSPICIOUS"
                else:
                    risk_level = "SAFE"
                    
                st.markdown("### 📊 Résultats du Rapport d'Analyse")
                
                if risk_level == "DANGEROUS":
                    st.error(f"🚨 **Statut : DANGEROUS** — Menace critique identifiée !")
                elif risk_level == "SUSPICIOUS":
                    st.warning(f"⚠️ **Statut : SUSPICIOUS** — Indicateurs mineurs ({suspicious} alertes).")
                else:
                    st.success(f"🟢 **Statut : SAFE** — Trafic sain.")
                    
                res1, res2, res3, res4 = st.columns(4)
                res1.metric("🔴 Malveillants", malicious)
                res2.metric("🟡 Suspects", suspicious)
                res3.metric("🟢 Inoffensifs", harmless)
                res4.metric("⚪ Non détectés", undetected)
                
                if supabase:
                    try:
                        data_to_insert = {
                            "url": url_to_analyze,
                            "risk_level": risk_level,
                            "malicious_count": malicious,
                            "suspicious_count": suspicious
                        }
                        supabase.table("analyses").insert(data_to_insert).execute()
                    except Exception as db_err:
                        st.warning(f"Note de stockage : Impossible d'enregistrer ({db_err})")

            except Exception as e:
                st.error(f"Une erreur technique est survenue : {e}")

# --- 7. HISTORIQUE RÉCENT ---
st.markdown("---")
st.subheader("📜 Journaux d'Analyse en Direct (Supabase)")

if supabase:
    try:
        response = supabase.table("analyses").select("*").order("created_at", desc=True).limit(10).execute()
        data = response.data
        
        if data:
            df = pd.DataFrame(data)
            
            if "url" in df.columns:
                display_df = df[["created_at", "url", "risk_level", "malicious_count", "suspicious_count"]].copy()
            else:
                display_df = df.copy()

            column_mapping = {
                "created_at": "Date & Heure",
                "url": "URL Analysée",
                "risk_level": "Niveau de Risque",
                "malicious_count": "Malveillants",
                "suspicious_count": "Suspects"
            }
            display_df = display_df.rename(columns={k: v for k, v in column_mapping.items() if k in display_df.columns})

            if "Date & Heure" in display_df.columns:
                display_df["Date & Heure"] = pd.to_datetime(display_df["Date & Heure"]).dt.strftime('%Y-%m-%d %H:%M:%S')

            st.table(display_df)
        else:
            st.info("Aucun journal d'analyse pour le moment.")
    except Exception as e:
        st.info("Impossible de charger les journaux.")
else:
    st.info("Base de données non connectée.")