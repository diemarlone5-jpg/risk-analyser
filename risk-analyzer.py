import streamlit as st
import pandas as pd
import requests
import base64
from supabase import create_client, Client

# --- 1. CONFIGURATION DE LA PAGE ---
st.set_page_config(
    page_title="URL Risk Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. INJECTION CSS POUR SUPPRIMER TOUS LES ARTÉFACTS ---
st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    [data-testid="stToolbar"] {display: none !important;}
    div[data-testid="stDecoration"] {display: none !important;}
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

# --- 4. BARRE LATÉRALE (SIDEBAR) EN FRANÇAIS ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-checked.png", width=80)
    st.header("URL Risk Analyzer")
    st.caption("Plateforme d'analyse de menaces web")
    
    st.markdown("---")
    st.subheader("État du système")
    
    if supabase:
        st.success("Base de données : Connectée")
    else:
        st.warning("Base de données : Hors-ligne")
        
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "TA_CLE_VIRUSTOTAL":
        st.success("Moteur VirusTotal : Actif")
    else:
        st.error("Moteur VirusTotal : Non configuré")
        
    st.markdown("---")
    st.subheader("Guide des Risques")
    st.markdown("""
    - **SÉCURISÉ** : Aucun signal malveillant.
    - **SUSPECT** : Signaux mineurs détectés.
    - **DANGEREUX** : Menace avérée / Malware / Phishing.
    """)
    st.markdown("---")
    st.info("💡 **Conseil** : Analysez systématiquement tout lien suspect.")

# --- 5. EN-TÊTE DE L'APPLICATION & CARTES DESIGN ---
st.title("🛡️ Tableau de bord d'analyse des risques liés aux URL")
st.markdown("Plateforme d'analyse avancée de menaces web propulsée par l'agrégation de plus de 70 moteurs de sécurité.")

# Les 3 cartes du haut (comme sur ta belle image 2)
col_m1, col_m2, col_m3 = st.columns(3)
with col_m1:
    st.markdown("### Moteur Cyber")
    st.markdown("#### VirusTotal v3")
with col_m2:
    st.markdown("### Stockage")
    st.markdown("#### Supabase Cloud")
with col_m3:
    st.markdown("### Niveau d'Analyse")
    st.markdown("#### Temps Réel (Hybride)")

st.markdown("---")

# --- 6. LOGIQUE D'ANALYSE INTELLIGENTE ---
st.subheader("🔍 Lancer une enquête")
url_to_analyze = st.text_input("Entrez l'URL complète à analyser :", placeholder="https://exemple.com")
analyze_button = st.button("Lancer l'analyse de sécurité", type="primary", use_container_width=True)

if analyze_button and url_to_analyze:
    if VIRUSTOTAL_API_KEY == "TA_CLE_VIRUSTOTAL":
        st.error("⚠️ Veuillez configurer votre clé API VirusTotal pour lancer l'analyse.")
    else:
        with st.spinner("🔄 Interrogation croisée des bases de données de menaces..."):
            try:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                
                # Cache VirusTotal via Base64
                url_bytes = url_to_analyze.encode("utf-8")
                url_id = base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")
                report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(report_url, headers=headers)
                
                stats = {}
                if response.status_code == 200:
                    attributes = response.json().get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                
                # Fallback POST si absent du cache
                if not stats or all(v == 0 for v in stats.values()):
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

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                if malicious > 0:
                    risk_level = "DANGEROUS"
                elif suspicious > 0:
                    risk_level = "SUSPICIOUS"
                else:
                    risk_level = "SAFE"
                    
                st.markdown("### 📊 Résultats du Rapport d'Analyse")
                
                if risk_level == "DANGEROUS":
                    st.error(f"🚨 **Statut : DANGEREUX** — Menace confirmée par **{malicious}** moteurs de sécurité !")
                elif risk_level == "SUSPICIOUS":
                    st.warning(f"⚠️ **Statut : SUSPECT** — Des signaux mineurs ont été détectés ({suspicious} alertes).")
                else:
                    st.success(f"🟢 **Statut : SÉCURISÉ** — Aucun moteur n'a détecté de menace active.")
                    
                res1, res2, res3, res4 = st.columns(4)
                res1.metric("🔴 Malveillants", malicious)
                res2.metric("🟡 Suspects", suspicious)
                res3.metric("🟢 Inoffensifs", harmless)
                res4.metric("⚪ Non détectés", undetected)
                
                if supabase:
                    try:
                        data_to_insert = {
                            "url": url_to_analyze,
                            "input_url": url_to_analyze,
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
st.subheader("📜 Historique des Analyses Récentes")

if supabase:
    try:
        response = supabase.table("analyses").select("*").order("created_at", desc=True).limit(10).execute()
        data = response.data
        
        if data:
            df = pd.DataFrame(data)
            
            if "url" in df.columns:
                display_df = df[["created_at", "url", "risk_level", "malicious_count", "suspicious_count"]].copy()
            elif "input_url" in df.columns:
                display_df = df[["created_at", "input_url", "risk_level", "malicious_count", "suspicious_count"]].copy()
                display_df.rename(columns={"input_url": "url"}, inplace=True)
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

            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Aucune analyse enregistrée pour le moment.")
    except Exception as e:
        st.info("Impossible de charger l'historique pour le moment.")
else:
    st.info("Base de données non connectée.")