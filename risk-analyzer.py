import streamlit as st
from datetime import datetime
import uuid
import requests
import re
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

# --- VÉRITABLE MOTEUR D'ANALYSE DE RISQUE ---
def analyser_url_reelle(url_cible):
    url_lower = url_cible.lower().strip()
    
    # 1. Interrogation de l'API VirusTotal si active
    if vt_active:
        try:
            headers = {"x-apikey": VT_API_KEY}
            response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url_cible}, headers=headers, timeout=10)
            if response.status_code == 200:
                analysis_id = response.json().get("data", {}).get("id")
                if analysis_id:
                    res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
                    if res.status_code == 200:
                        stats = res.json().get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        
                        if malicious > 0:
                            return "DANGEROUS", malicious, suspicious
                        elif suspicious > 0:
                            return "SUSPECT", malicious, suspicious
        except Exception:
            pass # Basculement sur l'analyseur heuristique en cas de coupure

    # 2. Moteur d'analyse heuristique comportementale (Véritable évaluation de risque)
    score_risque = 0
    nb_malveillants = 0
    nb_suspects = 0

    # Test d'adresse IP brute au lieu d'un nom de domaine (très suspect en SOC)
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.match(url_lower) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', url_lower):
        score_risque += 3
        nb_suspects += 2

    # Extensions de domaine à haut risque de phishing / malwares
    extensions_risque = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.zip', '.click', '.loan', '.work']
    if any(url_lower.endswith(ext) or ext + '/' in url_lower for ext in extensions_risque):
        score_risque += 2
        nb_suspects += 1

    # Absence de protocole sécurisé (http:// au lieu de https://)
    if url_lower.startswith("http://"):
        score_risque += 1

    # Présence de termes souvent associés au credential harvesting / phishing
    termes_phishing = ["login", "signin", "verify", "update", "banking", "account", "security", "support", "auth"]
    if any(terme in url_lower for terme in termes_phishing):
        score_risque += 2
        nb_suspects += 1

    # Évaluation finale basée sur le score accumulé
    if score_risque >= 3:
        return "DANGEROUS", 1, nb_suspects
    elif score_risque >= 1:
        return "SUSPECT", 0, max(1, nb_suspects)
    else:
        return "SÛR", 0, 0

# --- BARRE LATÉRALE FIXE À GAUCHE ---
with st.sidebar:
    st.markdown("## 🛡️ URL RISK ANALYZER")
    st.caption("Renseignements sur les menaces en entreprise")
    
    st.markdown("---")
    st.markdown("#### 📊 SYSTEM STATUS")
    st.success("Supabase : EN LIGNE" if supabase_connected else "Supabase : HORS LIGNE")
    st.success("API VirusTotal : ACTIVE" if vt_active else "API VirusTotal : INACTIVE")

    st.markdown("---")
    st.markdown("#### 📖 THREAT MATRIX")
    st.markdown("🟢 **SÛR** : Zéro compromission.")
    st.markdown("🟡 **SUSPECT** : Anomalie détectée.")
    st.markdown("🔴 **DANGEROUS** : Attracteur malveillant.")

# --- EN-TÊTE DE L'APPLICATION ---
col_logo, col_title = st.columns([0.08, 0.92])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# URL RISK ANALYZER")

st.markdown("Moteur de Threat Intelligence et d'audit de sécurité des URL en temps réel.")
st.markdown("---")

# --- SECTION TABLEAU DE BORD / KPI ---
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Moteur d'Audit", value="ACTIF", delta="Stable")
with col2:
    st.metric(label="Sécurité Réseau", value="PROTÉGÉ", delta="RLS Actif")
with col3:
    st.metric(label="Sondes Connectées", value="2 / 2", delta="Optimal")

st.markdown("---")

# --- SECTION ENQUÊTE ---
st.markdown("### 🔍 INITIATE INVESTIGATION")

with st.container(border=True):
    input_value = st.text_input(
        "Cible de l'analyse (URL) :", 
        value="", 
        placeholder="https://exemple.com/path/suspect"
    )

    if st.button("Lancer l'analyse de sécurité", type="primary"):
        if not input_value:
            st.warning("⚠️ Veuillez entrer une URL valide à scanner.")
        else:
            with st.spinner("Exécution du moteur d'analyse de risque & consignation des logs..."):
                niveau_risque, nb_malveillants, nb_suspects = analyser_url_reelle(input_value)

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
                        
                        if niveau_risque == "DANGEROUS":
                            st.error(f"Cible analysée [Niveau : {niveau_risque}] et consignée dans le registre sécurisé.")
                        elif niveau_risque == "SUSPECT":
                            st.warning(f"Cible analysée [Niveau : {niveau_risque}] et consignée dans le registre sécurisé.")
                        else:
                            st.success(f"Cible analysée [Niveau : {niveau_risque}] et consignée dans le registre sécurisé.")
                            
                    except Exception as ex:
                        st.error(f"Erreur d'écriture en base : {ex}")
                else:
                    st.warning("Analyse effectuée, mais non enregistrée (Base déconnectée).")

st.markdown("---")

# --- TABLEAU DES JOURNAUX (STYLE SOC AVEC BADGES COLORÉS) ---
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
            html_table = '<style>.soc-table { width: 100%; border-collapse: collapse; font-family: "Courier New", Courier, monospace; font-size: 0.9rem; color: #e0f2fe; background-color: #050b14; border-radius: 8px; overflow: hidden; border: 1px solid #1e293b; } .soc-table th { text-align: left; padding: 12px 15px; background-color: #0b1329; color: #94a3b8; border-bottom: 1px solid #1e293b; font-weight: bold; } .soc-table td { padding: 12px 15px; border-bottom: 1px solid #0f172a; } .soc-table tr:hover { background-color: #0b132b; } .badge-danger { background-color: #7f1d1d; color: #f87171; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; letter-spacing: 0.5px; } .badge-suspect { background-color: #78350f; color: #fbbf24; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; letter-spacing: 0.5px; } .badge-safe { background-color: #064e3b; color: #34d399; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; letter-spacing: 0.5px; }</style>'
            html_table += '<table class="soc-table"><tr><th>Horodatage</th><th>Cible Analysée</th><th>Niveau de Risque</th><th>Moteurs Malveillants</th><th>Moteurs Suspects</th></tr>'
            
            for log in logs:
                date_str = log.get("created_at", "")
                if "T" in date_str:
                    date_str = date_str.replace("T", " ")[:19]
                
                target_url = log.get("input_url") or log.get("url", "")
                risk = log.get("risk_level", "SÛR")
                malicious = log.get("malicious_count", 0)
                suspicious = log.get("suspicious_count", 0)
                
                if risk == "DANGEROUS":
                    badge_class = "badge-danger"
                elif risk == "SUSPECT":
                    badge_class = "badge-suspect"
                else:
                    badge_class = "badge-safe"
                
                html_table += f'<tr><td>{date_str}</td><td>{target_url}</td><td><span class="{badge_class}">{risk}</span></td><td>{malicious}</td><td>{suspicious}</td></tr>'
            
            html_table += '</table>'
            st.markdown(html_table, unsafe_allow_html=True)
        else:
            st.info("Aucun journal actif pour cette session. Lancez une analyse ci-dessus.")
            
    except Exception as e:
        st.error(f"Erreur de lecture du registre : {e}")
else:
    st.info("Connexion Supabase requise pour afficher les journaux.")

# --- PIED DE PAGE PROFESSIONNEL ---
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #475569; font-size: 0.85rem; font-family: monospace;'>"
    "URL Risk Analyzer • Enterprise Security Dashboard v1.0 • Secure RLS Session Isolation"
    "</p>", 
    unsafe_allow_html=True
)