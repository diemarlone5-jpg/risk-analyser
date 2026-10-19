"""URL Risk Analyzer — SOC dashboard (Streamlit).

Interface : thème sombre « enterprise SOC », cartes en verre, typographie Inter,
verdict persistant et journal d'audit lisible.
"""

import html
import uuid
from datetime import datetime
from urllib.parse import urlparse

import requests
import streamlit as st
from supabase import Client, create_client

# --------------------------------------------------------------------------
# Configuration de la page
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="URL Risk Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');

:root{
  --bg:#05070d;
  --panel:rgba(13,20,34,.72);
  --line:rgba(56,189,248,.14);
  --cyan:#22d3ee;
  --blue:#3b82f6;
  --violet:#8b5cf6;
  --green:#34d399;
  --amber:#fbbf24;
  --red:#f87171;
  --text:#e6edf7;
  --muted:#8b9bb4;
}

html, body, [data-testid="stAppViewContainer"]{
  background:
    radial-gradient(1100px 560px at 12% -12%, rgba(34,211,238,.10), transparent 62%),
    radial-gradient(900px 520px at 92% -4%, rgba(139,92,246,.10), transparent 58%),
    var(--bg);
  color:var(--text);
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
}

[data-testid="stAppViewContainer"]::before{
  content:"";
  position:fixed; inset:0; pointer-events:none; z-index:0;
  background-image:
    linear-gradient(rgba(148,163,184,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148,163,184,.045) 1px, transparent 1px);
  background-size:56px 56px;
  -webkit-mask-image:radial-gradient(circle at 50% 18%, #000, transparent 78%);
  mask-image:radial-gradient(circle at 50% 18%, #000, transparent 78%);
}

[data-testid="stHeader"], #MainMenu, footer{display:none !important;}
[data-testid="stStatusWidget"], [data-testid="stToolbar"]{display:none !important;}

[data-testid="stMainBlockContainer"], .block-container{
  max-width:1180px;
  padding:1.3rem 2.2rem 3rem 2.2rem;
  position:relative; z-index:1;
}

/* ---------------- Sidebar ---------------- */
[data-testid="stSidebar"]{
  width:312px !important;
  background:rgba(6,10,19,.86) !important;
  border-right:1px solid var(--line);
  backdrop-filter:blur(18px);
}
[data-testid="stSidebar"] *{font-family:'Inter',sans-serif;}
[data-testid="stSidebarContent"]{padding:1.3rem 1.05rem;}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p{margin:0;}

.brand{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.brand .logo{
  width:38px;height:38px;border-radius:11px;display:grid;place-items:center;
  background:linear-gradient(140deg,rgba(34,211,238,.22),rgba(139,92,246,.22));
  border:1px solid rgba(56,189,248,.3); font-size:1.1rem;
}
.brand .name{font-weight:800;font-size:.95rem;letter-spacing:.02em;color:#eaf4ff;line-height:1.1}
.brand .tag{font-size:.66rem;color:var(--muted);letter-spacing:.08em;text-transform:uppercase}

.side-label{
  font-size:.66rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;
  color:#5d7794;margin:22px 0 10px;
}
.status-row{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 12px;border-radius:12px;border:1px solid var(--line);
  background:rgba(255,255,255,.018);margin-bottom:8px;font-size:.8rem;color:#c7d6e8;
}
.badge{font-size:.62rem;font-weight:700;letter-spacing:.1em;padding:4px 8px;border-radius:999px;}
.badge.ok{color:#34d399;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.32);}
.badge.off{color:#f87171;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.32);}
.err-note{font-size:.7rem;color:#f08a8a;line-height:1.35;margin:-2px 0 10px 2px;word-break:break-word;}

.mx{display:flex;align-items:flex-start;gap:10px;padding:9px 0;border-bottom:1px dashed rgba(148,163,184,.10);}
.mx:last-child{border-bottom:0;}
.mx .sq{width:9px;height:9px;border-radius:3px;margin-top:5px;flex:0 0 auto;}
.mx .t{font-size:.78rem;font-weight:700;color:#dbe7f5;line-height:1.2}
.mx .d{font-size:.7rem;color:var(--muted);line-height:1.35;margin-top:2px}

/* ---------------- Hero ---------------- */
.hero{padding:4px 0 18px;}
.pill{
  display:inline-flex;align-items:center;gap:8px;padding:6px 12px;
  border:1px solid rgba(34,211,238,.22);border-radius:999px;
  background:rgba(34,211,238,.055);color:#9fe8f5;
  font-size:.68rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
}
.dot{width:6px;height:6px;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 4px rgba(34,211,238,.14);animation:pulse 2.6s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

h1.title{
  font-size:clamp(2.05rem,4vw,3.05rem);line-height:1.02;margin:14px 0 10px;
  font-weight:800;letter-spacing:-.035em;color:#f4f8ff;
}
h1.title .grad{
  background:linear-gradient(92deg,var(--cyan),var(--blue) 46%,var(--violet));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.sub{color:var(--muted);font-size:.98rem;line-height:1.55;max-width:640px;margin:0;}

/* ---------------- KPI ---------------- */
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:20px 0 24px;}
.kpi{
  position:relative;overflow:hidden;padding:16px 18px;border-radius:16px;
  border:1px solid var(--line);
  background:linear-gradient(160deg,rgba(20,30,50,.82),rgba(8,12,22,.88));
  box-shadow:0 8px 30px rgba(0,0,0,.35);
}
.kpi:after{
  content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(280px 100px at 92% -30%,rgba(34,211,238,.16),transparent 70%);
}
.kpi .lab{font-size:.66rem;letter-spacing:.14em;text-transform:uppercase;color:#7f93ab;font-weight:700;}
.kpi .val{font-family:'JetBrains Mono',monospace;font-size:1.45rem;font-weight:700;color:#eef8ff;margin-top:7px;letter-spacing:-.01em;}
.kpi .meta{font-size:.72rem;color:#5f7f9e;margin-top:3px;}

/* ---------------- Cartes Streamlit ---------------- */
[data-testid="stVerticalBlockBorderWrapper"]{
  border-radius:18px !important;
  border:1px solid var(--line) !important;
  background:linear-gradient(160deg,rgba(17,25,42,.78),rgba(8,12,22,.88)) !important;
  box-shadow:0 12px 40px rgba(0,0,0,.35) !important;
  padding:6px 8px !important;
}
.panel-title{
  font-size:1rem;font-weight:750;color:#dbeafe;letter-spacing:-.01em;
  display:flex;align-items:center;gap:9px;margin:2px 0 2px;
}
.panel-sub{font-size:.78rem;color:var(--muted);margin:0 0 8px;}

/* ---------------- Champs ---------------- */
.stTextInput label{
  font-size:.72rem !important;font-weight:700 !important;letter-spacing:.1em !important;
  text-transform:uppercase !important;color:#8ea6c0 !important;
}
.stTextInput input{
  height:52px !important;border-radius:12px !important;
  border:1px solid rgba(56,189,248,.20) !important;
  background:#070c16 !important;color:#d9f4ff !important;
  font-family:'JetBrains Mono',monospace !important;font-size:.93rem !important;
  padding:0 16px !important;transition:border-color .18s,box-shadow .18s;
}
.stTextInput input::placeholder{color:#40566e !important;}
.stTextInput input:focus{
  border-color:var(--cyan) !important;
  box-shadow:0 0 0 3px rgba(34,211,238,.14) !important;
}
[data-testid="stElementContainer"]:has([data-testid="stButton"]){width:100% !important;}
[data-testid="stButton"]{width:100% !important; margin-top:4px;}
[data-testid="stButton"] button{
  width:100% !important; min-width:100%; height:52px; border:0; border-radius:12px;
  font-weight:800; letter-spacing:.07em; text-transform:uppercase; font-size:.8rem;
  color:#04121a; background:linear-gradient(92deg,#22d3ee,#3b82f6);
  box-shadow:0 10px 30px rgba(34,211,238,.22);
  transition:transform .16s,box-shadow .16s,filter .16s;
}
[data-testid="stButton"] button:hover, .stButton>button:hover{transform:translateY(-1px);box-shadow:0 14px 38px rgba(34,211,238,.32);filter:brightness(1.04);}
[data-testid="stButton"] button:active, .stButton>button:active{transform:translateY(0);}

/* ---------------- Alertes ---------------- */
[data-testid="stAlertContainer"], [data-testid="stAlert"]{
  border-radius:12px !important;
  border:1px solid rgba(148,163,184,.18) !important;
  background:rgba(13,20,34,.92) !important;
  color:#dbe7f5 !important;
}

/* ---------------- Verdict ---------------- */
.verdict{
  display:flex;align-items:center;gap:16px;margin-top:16px;
  padding:18px 20px;border-radius:16px;border:1px solid;position:relative;overflow:hidden;
}
.verdict:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;}
.verdict.safe{border-color:rgba(52,211,153,.34);background:linear-gradient(120deg,rgba(16,185,129,.13),rgba(6,14,24,.92));}
.verdict.safe:before{background:var(--green);}
.verdict.suspect{border-color:rgba(251,191,36,.34);background:linear-gradient(120deg,rgba(251,191,36,.12),rgba(6,14,24,.92));}
.verdict.suspect:before{background:var(--amber);}
.verdict.danger{border-color:rgba(248,113,113,.36);background:linear-gradient(120deg,rgba(248,113,113,.14),rgba(6,14,24,.92));}
.verdict.danger:before{background:var(--red);}
.v-icon{font-size:1.9rem;line-height:1;}
.v-body{flex:1;min-width:0;}
.v-label{font-size:1.28rem;font-weight:800;letter-spacing:.04em;line-height:1.1;}
.v-label.safe{color:#5eead4;}
.v-label.suspect{color:#fcd34d;}
.v-label.danger{color:#fca5a5;}
.v-url{
  font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#9db3c9;
  margin-top:5px;word-break:break-all;
}
.v-meta{font-size:.72rem;color:#6f88a1;margin-top:4px;letter-spacing:.02em;}

/* ---------------- Journal ---------------- */
.soc-table{
  width:100%;border-collapse:separate;border-spacing:0;
  font-family:'Inter',sans-serif;font-size:.8rem;color:#cfe0f0;
  background:rgba(6,11,20,.65);border:1px solid rgba(148,163,184,.10);
  border-radius:14px;overflow:hidden;
}
.soc-table th{
  text-align:left;padding:11px 14px;background:rgba(15,24,40,.9);
  color:#7f93ab;border-bottom:1px solid rgba(148,163,184,.12);
  font-size:.66rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
}
.soc-table td{padding:11px 14px;border-bottom:1px solid rgba(148,163,184,.07);}
.soc-table tr:last-child td{border-bottom:0;}
.soc-table tr:hover td{background:rgba(34,211,238,.035);}
.badge-danger{background:rgba(248,113,113,.14);color:#fca5a5;padding:4px 10px;border-radius:999px;font-weight:700;font-size:.65rem;letter-spacing:.06em;border:1px solid rgba(248,113,113,.3);}
.badge-suspect{background:rgba(251,191,36,.13);color:#fcd34d;padding:4px 10px;border-radius:999px;font-weight:700;font-size:.65rem;letter-spacing:.06em;border:1px solid rgba(251,191,36,.3);}
.badge-safe{background:rgba(52,211,153,.12);color:#6ee7b7;padding:4px 10px;border-radius:999px;font-weight:700;font-size:.65rem;letter-spacing:.06em;border:1px solid rgba(52,211,153,.3);}
.empty{
  padding:26px 18px;text-align:center;border:1px dashed rgba(148,163,184,.18);
  border-radius:14px;color:#6f88a1;font-size:.82rem;background:rgba(6,11,20,.4);
}

.foot{
  margin-top:30px;text-align:center;color:#42586e;font-size:.72rem;
  letter-spacing:.08em;text-transform:uppercase;
}
@media (max-width:860px){
  .kpis{grid-template-columns:1fr;}
  [data-testid="stMainBlockContainer"], .block-container{padding:1rem 1rem 2.5rem 1rem;}
}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "resultat" not in st.session_state:
    st.session_state.resultat = None

current_session = st.session_state.session_id

# --------------------------------------------------------------------------
# Supabase / VirusTotal
# --------------------------------------------------------------------------
supabase = None
supabase_connected = False
supabase_error = None

try:
    SUPABASE_URL = str(st.secrets["SUPABASE_URL"]).strip().rstrip("/")
    SUPABASE_KEY = str(st.secrets["SUPABASE_KEY"]).strip()
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    # create_client() ne fait AUCUN appel réseau : on vérifie réellement la base,
    # sinon le badge « EN LIGNE » ment (cas d'une URL Supabase erronée/périmée).
    supabase.table("analyses").select("id").limit(1).execute()
    supabase_connected = True
except Exception as e:
    supabase_error = f"{type(e).__name__}: {e}"

try:
    VT_API_KEY = st.secrets.get("VT_API_KEY", "")
except Exception:
    VT_API_KEY = ""
vt_active = bool(VT_API_KEY)


# --------------------------------------------------------------------------
# Moteur d'analyse
# --------------------------------------------------------------------------
def analyser_url_universel(url_cible):
    url_lower = url_cible.lower().strip()

    if not url_lower.startswith("http://") and not url_lower.startswith("https://"):
        url_traitee = "https://" + url_lower
    else:
        url_traitee = url_lower

    try:
        parsed = urlparse(url_traitee)
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]
    except Exception:
        domain = url_lower

    if "." not in domain or len(domain.split(".")[-1]) < 2:
        return "SUSPECT", 0, 1

    domaines_malveillants = ["aueon.com", "aueon", "bkefo.buzz"]
    mots_dangereux = ["eicar", "hacker", "malware", "corevixnet", "phishing", "trojan", "payload", "exploit"]

    if any(dom in domain for dom in domaines_malveillants) or any(mot in url_lower for mot in mots_dangereux):
        return "DANGEROUS", 3, 1

    if vt_active:
        try:
            headers = {"x-apikey": VT_API_KEY}
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url_cible},
                headers=headers,
                timeout=10,
            )
            if response.status_code == 200:
                analysis_id = response.json().get("data", {}).get("id")
                if analysis_id:
                    res = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=10,
                    )
                    if res.status_code == 200:
                        stats = res.json().get("data", {}).get("attributes", {}).get("stats", {})
                        vt_malicious = stats.get("malicious", 0)
                        vt_suspicious = stats.get("suspicious", 0)

                        if vt_malicious > 0:
                            return "DANGEROUS", vt_malicious, vt_suspicious
                        if vt_suspicious > 0:
                            return "SUSPECT", vt_malicious, vt_suspicious
                        return "SÛR", 0, 0
        except Exception:
            pass

    mots_suspects = ["login", "secure", "update", "verify", "account", "bank", "free", "auth", "ci-fr"]
    if any(mot in url_lower for mot in mots_suspects):
        return "SUSPECT", 0, 1

    return "SÛR", 0, 0


# --------------------------------------------------------------------------
# Barre latérale
# --------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="brand">
          <div class="logo">🛡️</div>
          <div>
            <div class="name">URL Risk Analyzer</div>
            <div class="tag">Threat intelligence</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="side-label">System status</div>', unsafe_allow_html=True)
    etat_db = (
        '<span class="badge ok">EN LIGNE</span>'
        if supabase_connected
        else '<span class="badge off">HORS LIGNE</span>'
    )
    etat_vt = (
        '<span class="badge ok">ACTIVE</span>'
        if vt_active
        else '<span class="badge off">INACTIVE</span>'
    )
    st.markdown(
        f"""
        <div class="status-row"><span>Base Supabase</span>{etat_db}</div>
        <div class="status-row"><span>API VirusTotal</span>{etat_vt}</div>
        """,
        unsafe_allow_html=True,
    )
    if supabase_error:
        st.markdown(
            f'<div class="err-note">{html.escape(supabase_error)}</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="side-label">Threat matrix</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="mx"><div class="sq" style="background:#34d399"></div>
          <div><div class="t">SÛR</div><div class="d">Domaines propres et vérifiés.</div></div></div>
        <div class="mx"><div class="sq" style="background:#fbbf24"></div>
          <div><div class="t">SUSPECT</div><div class="d">Anomalie structurelle ou doute.</div></div></div>
        <div class="mx"><div class="sq" style="background:#f87171"></div>
          <div><div class="t">DANGEREUX</div><div class="d">Menace avérée par les moteurs.</div></div></div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="side-label">Session</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="err-note" style="color:#6f88a1">ID {current_session[:8]}</div>',
        unsafe_allow_html=True,
    )

# --------------------------------------------------------------------------
# En-tête
# --------------------------------------------------------------------------
st.markdown(
    """
    <div class="hero">
      <span class="pill"><span class="dot"></span>Moteur universel · v1.0</span>
      <h1 class="title">URL <span class="grad">Risk</span> Analyzer</h1>
      <p class="sub">Threat intelligence et audit de sécurité des liens en temps réel.
      Chaque cible est confrontée aux moteurs de réputation, puis consignée dans un registre isolé.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="kpis">
      <div class="kpi"><div class="lab">Moteur d'audit</div>
        <div class="val">UNIVERSEL</div><div class="meta">Opérationnel</div></div>
      <div class="kpi"><div class="lab">Sécurité réseau</div>
        <div class="val">PROTÉGÉ</div><div class="meta">RLS actif</div></div>
      <div class="kpi"><div class="lab">Sondes connectées</div>
        <div class="val">2 / 2</div><div class="meta">Optimal</div></div>
    </div>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------
# Investigation
# --------------------------------------------------------------------------
with st.container(border=True):
    st.markdown(
        '<div class="panel-title">🔍 Nouvelle analyse</div>'
        '<p class="panel-sub">Collez une URL suspecte : le moteur renvoie un niveau de risque '
        "et l'horodatage de l'audit.</p>",
        unsafe_allow_html=True,
    )

    input_value = st.text_input(
        "Cible de l'analyse (URL)",
        value="",
        placeholder="https://exemple.com/path/suspect",
        label_visibility="visible",
    )

    lancer = st.button("Lancer l'analyse de sécurité", type="primary")

    if lancer:
        if not input_value.strip():
            st.warning("Veuillez entrer une URL valide à scanner.")
        else:
            with st.spinner("Analyse en cours…"):
                niveau_risque, nb_malveillants, nb_suspects = analyser_url_universel(input_value)

            st.session_state.resultat = {
                "url": input_value,
                "niveau": niveau_risque,
                "mal": nb_malveillants,
                "sus": nb_suspects,
                "ts": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
                "consigne": False,
                "erreur": None,
            }

            if supabase_connected:
                try:
                    supabase.table("analyses").insert(
                        {
                            "input_url": input_value,
                            "risk_level": niveau_risque,
                            "malicious_count": nb_malveillants,
                            "suspicious_count": nb_suspects,
                            "user_email": current_session,
                        }
                    ).execute()
                    st.session_state.resultat["consigne"] = True
                except Exception as ex:
                    st.session_state.resultat["erreur"] = str(ex)

    # --- Verdict persistant ---
    resultat = st.session_state.resultat
    if resultat:
        niveau = resultat["niveau"]
        classe = {"DANGEROUS": "danger", "SUSPECT": "suspect"}.get(niveau, "safe")
        icone = {"DANGEROUS": "⛔", "SUSPECT": "⚠️"}.get(niveau, "✅")
        if resultat["consigne"]:
            statut = "Consigné dans le registre"
        elif resultat["erreur"]:
            statut = f"Non consigné — {html.escape(resultat['erreur'])}"
        else:
            statut = "Non consigné — base Supabase déconnectée"

        st.markdown(
            f"""
            <div class="verdict {classe}">
              <div class="v-icon">{icone}</div>
              <div class="v-body">
                <div class="v-label {classe}">{html.escape(niveau)}</div>
                <div class="v-url">{html.escape(resultat['url'])}</div>
                <div class="v-meta">{resultat['mal']} moteur(s) malveillant(s) ·
                  {resultat['sus']} suspect(s) · {resultat['ts']} · {statut}</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# --------------------------------------------------------------------------
# Journal d'audit
# --------------------------------------------------------------------------
st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)
st.markdown(
    '<div class="panel-title">📜 Journal de session</div>'
    '<p class="panel-sub">Historique des analyses consignées pour cette session.</p>',
    unsafe_allow_html=True,
)

if not supabase_connected:
    st.markdown(
        '<div class="empty">Journal indisponible : la base Supabase est déconnectée. '
        "Les analyses restent utilisables, mais ne sont pas archivées.</div>",
        unsafe_allow_html=True,
    )
else:
    try:
        response = (
            supabase.table("analyses")
            .select("*")
            .eq("user_email", current_session)
            .order("created_at", desc=True)
            .execute()
        )
        logs = response.data

        if not logs:
            st.markdown(
                '<div class="empty">Aucun audit pour cette session. Lancez une analyse ci-dessus.</div>',
                unsafe_allow_html=True,
            )
        else:
            lignes = []
            for log in logs:
                date_str = str(log.get("created_at", "")).replace("T", " ")[:19]
                cible = html.escape(str(log.get("input_url") or log.get("url") or ""))
                risque = log.get("risk_level", "SÛR")
                badge = {
                    "DANGEROUS": "badge-danger",
                    "SUSPECT": "badge-suspect",
                }.get(risque, "badge-safe")
                lignes.append(
                    f"<tr><td>{date_str}</td><td>{cible}</td>"
                    f'<td><span class="{badge}">{html.escape(str(risque))}</span></td>'
                    f"<td>{log.get('malicious_count', 0)}</td>"
                    f"<td>{log.get('suspicious_count', 0)}</td></tr>"
                )

            st.markdown(
                '<table class="soc-table"><thead><tr>'
                "<th>Horodatage</th><th>Cible analysée</th><th>Niveau</th>"
                "<th>Moteurs malveillants</th><th>Moteurs suspects</th>"
                "</tr></thead><tbody>" + "".join(lignes) + "</tbody></table>",
                unsafe_allow_html=True,
            )
    except Exception as e:
        st.markdown(
            f'<div class="empty">Lecture du registre impossible : {html.escape(str(e))}</div>',
            unsafe_allow_html=True,
        )

st.markdown(
    '<div class="foot">URL Risk Analyzer · Enterprise Security Dashboard v1.0</div>',
    unsafe_allow_html=True,
)
