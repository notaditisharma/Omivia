"""OMIVIA - identity-based brute force and password spray detection (no IPs)."""
import base64
import html
import io
import json
import traceback
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

import legal
import store

BASE = Path(__file__).resolve().parent
LOGO = BASE / "omivialogo.png"

st.set_page_config(page_title="OMIVIA", page_icon=str(LOGO) if LOGO.exists() else None,
                   layout="wide", initial_sidebar_state="expanded")

# Palette derived from the logo's deep indigo. Red/amber/green are reserved for severity and outcomes.
# Every text/background pair below is chosen to meet WCAG AA (4.5:1).
def system_theme():
    try:
        return "Light" if st.context.theme.type == "light" else "Dark"
    except Exception:
        return "Dark"


PALETTES = {
    "Dark": dict(BG="#0E0D1A", SIDE="#131227", SURF="#181730", SURF2="#211F3E", BORDER="#34315A", TEXT="#ECEBF5",
                 MUTED="#9593B2", ACCENT="#8F86E0", ACCENT_D="#3B3577", ON_ACCENT="#0E0D1A", CYAN="#5FB4D9",
                 RED="#EF5B63", AMBER="#E9B04B", GREEN="#45BE90"),
    "Light": dict(BG="#F3F3F8", SIDE="#FFFFFF", SURF="#FFFFFF", SURF2="#ECEAF6", BORDER="#CFCCE2", TEXT="#1E1B3A",
                  MUTED="#5F5D7C", ACCENT="#5A4FCF", ACCENT_D="#DCD8F6", ON_ACCENT="#FFFFFF", CYAN="#1F7FA8",
                  RED="#C0323C", AMBER="#92600A", GREEN="#1E7A55"),
}
for _k, _v in {"theme": system_theme(), "compact": False, "notify": True, "notified": []}.items():
    st.session_state.setdefault(_k, _v)
C = PALETTES[st.session_state.theme]
SEV = {"Critical": C["RED"], "High": C["AMBER"]}
TYPE_COLOR = {"Brute Force": C["ACCENT"], "Password Spray": C["CYAN"]}
PAGES = ["Overview", "Incidents", "Targeted Accounts", "Investigate", "Detection Rules", "Settings"]
STATUSES = ["New", "Investigating", "Contained", "False positive"]
DEFAULT_RULES = {"window": 15, "bf_min": 20, "sp_accts": 15, "sp_max": 3}

for k, v in {"auth": False, "user": "", "email": None, "uid": None, "ai_training": False, "bad_route": None, "qp_done": False, "page": "Overview", "status": {}, "rules": dict(DEFAULT_RULES)}.items():
    st.session_state.setdefault(k, v)

FONT = '"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif'

st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');
html, body, .stApp, button, input, textarea {{ font-family:{FONT}; }}
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {{ background:{C['BG']}; color:{C['TEXT']}; }}
[data-testid="stHeader"] {{ background:transparent; }}
[data-testid="stHeader"] * {{ color:{C['TEXT']}; }}
.stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4, div[role="dialog"] h1, div[role="dialog"] h2, div[role="dialog"] p, div[role="dialog"] li, div[role="dialog"] label {{ color:{C['TEXT']}; }}
.stApp p, .stApp li {{ font-size:14px; line-height:1.55; }}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {{ color:{C['MUTED']}; font-size:13px; }}
.stApp a {{ color:{C['ACCENT']}; text-decoration:none; }}
.stApp a:hover {{ text-decoration:underline; }}
:focus-visible {{ outline:2px solid {C['ACCENT']} !important; outline-offset:2px; }}
.block-container {{ max-width:1320px; padding:{'1rem 1.25rem 2rem' if st.session_state.compact else '2rem 2rem 3rem'}; }}
#MainMenu, footer {{ visibility:hidden; }}
section[data-testid="stSidebar"], section[data-testid="stSidebar"] > div {{ background:{C['SIDE']}; }}
section[data-testid="stSidebar"] {{ border-right:1px solid {C['BORDER']}; }}
section[data-testid="stSidebar"] div[role="radiogroup"] {{ gap:2px; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label {{ width:100%; padding:7px 10px; border-radius:6px; transition:background-color .2s ease; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child {{ display:none; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{ background:{C['ACCENT']}12; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {{ background:{C['ACCENT']}24; font-weight:600; }}
input, textarea, [data-baseweb="select"] > div, [data-baseweb="base-input"] {{ background:{C['SURF']} !important; color:{C['TEXT']} !important; border-color:{C['BORDER']} !important; }}
[data-baseweb="select"] > div, [data-baseweb="base-input"], [data-baseweb="textarea"] {{ border-radius:6px !important; }}
[data-baseweb="select"] svg {{ fill:{C['MUTED']}; }}
[data-baseweb="popover"], [data-baseweb="popover"] > div, [data-baseweb="menu"], [role="listbox"], [role="option"] {{ background:{C['SURF']} !important; color:{C['TEXT']} !important; }}
[role="option"]:hover, [role="option"][aria-selected="true"] {{ background:{C['SURF2']} !important; }}
span[data-baseweb="tag"] {{ background:{C['ACCENT_D']} !important; color:{C['TEXT']} !important; }}
[data-testid^="stBaseButton"] {{ border-radius:6px; min-height:36px; font-weight:500; }}
[data-testid^="stBaseButton-secondary"] {{ background:{C['SURF']}; color:{C['TEXT']}; border:1px solid {C['BORDER']}; }}
[data-testid^="stBaseButton-secondary"]:hover {{ background:{C['SURF2']}; border-color:{C['BORDER']}; }}
[data-testid="stBaseButton-primary"] {{ background:{C['ACCENT']}; border:1px solid {C['ACCENT']}; }}
[data-testid="stBaseButton-primary"] p {{ color:{C['ON_ACCENT']}; font-weight:500; }}
[data-testid="stBaseButton-tertiary"] {{ background:transparent; min-height:28px; }}
[data-testid="stBaseButton-tertiary"] p {{ color:{C['MUTED']}; font-size:13px; }}
[data-testid="stBaseButton-tertiary"]:hover p {{ color:{C['TEXT']}; text-decoration:underline; }}
[data-testid^="stBaseButton"] {{ transition:none !important; }}
button:disabled {{ opacity:.55; }}
[data-testid="stExpander"] details {{ background:{C['SURF']}; border:1px solid {C['BORDER']}; border-radius:8px; }}
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * {{ color:{C['TEXT']}; }}
[data-testid="stAlert"] {{ background:{C['SURF2']}; border:1px solid {C['BORDER']}; border-radius:8px; }}
[data-testid="stAlert"] * {{ color:{C['TEXT']}; }}
div[role="dialog"], div[role="dialog"] > div {{ background:{C['SURF']}; color:{C['TEXT']}; border-radius:10px; }}
[data-testid="stToast"] {{ background:{C['SURF']}; color:{C['TEXT']}; border:1px solid {C['BORDER']}; }}
[data-testid="stFileUploaderDropzone"] {{ background:{C['SURF2']}; border:1px dashed {C['BORDER']}; border-radius:8px; }}
[data-testid="stFileUploaderDropzone"] small, [data-testid="stFileUploaderDropzone"] span {{ color:{C['MUTED']}; }}
button[role="tab"] {{ color:{C['MUTED']}; transition:color .2s ease; }}
button[role="tab"][aria-selected="true"] {{ color:{C['TEXT']}; }}
[data-testid="stSlider"] [role="slider"] {{ background:{C['ACCENT']}; }}
[data-testid="stSliderThumbValue"] {{ color:{C['ACCENT']}; }}
hr {{ border-color:{C['BORDER']}; margin:0; }}
div[data-testid="stMetric"] {{ background:{C['SURF']}; border:1px solid {C['BORDER']}; border-radius:8px; padding:14px 16px; }}
div[data-testid="stMetricLabel"] p {{ font-size:12px; font-weight:500; color:{C['MUTED']}; }}
div[data-testid="stMetricValue"] {{ font-size:26px; font-weight:600; color:{C['TEXT']}; font-variant-numeric:tabular-nums; }}
div[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:8px; background:{C['SURF']}; border-color:{C['BORDER']}; }}
.page-head {{ padding-bottom:16px; margin-bottom:24px; border-bottom:1px solid {C['BORDER']}; }}
.page-title {{ font-size:24px; font-weight:600; letter-spacing:-.2px; color:{C['TEXT']}; }}
.page-sub {{ font-size:14px; color:{C['MUTED']}; margin-top:4px; }}
.card-title {{ font-size:14px; font-weight:600; color:{C['TEXT']}; }}
.card-sub {{ font-size:13px; color:{C['MUTED']}; margin:2px 0 12px; }}
.brand {{ font-size:16px; font-weight:600; color:{C['TEXT']}; line-height:1.2; }}
.brand-sub {{ font-size:12px; color:{C['MUTED']}; }}
.logo {{ border-radius:8px; }}
.chip {{ margin-top:16px; font-size:12px; line-height:1.6; color:{C['MUTED']}; }}
.chip b {{ color:{C['GREEN']}; font-weight:600; }}
.tbl {{ overflow:auto; border:1px solid {C['BORDER']}; border-radius:8px; background:{C['SURF']}; max-height:460px; }}
.tbl table {{ width:100%; border-collapse:collapse; font-size:13px; font-variant-numeric:tabular-nums; }}
.tbl th {{ text-align:left; font-size:12px; font-weight:600; color:{C['MUTED']}; padding:10px 16px; border-bottom:1px solid {C['BORDER']}; white-space:nowrap; position:sticky; top:0; background:{C['SURF2']}; }}
.tbl td {{ transition:background-color .2s ease; padding:10px 16px; border-bottom:1px solid {C['BORDER']}; color:{C['TEXT']}; white-space:nowrap; }}
.tbl tbody tr:last-child td {{ border-bottom:0; }}
.tbl tbody tr:hover td {{ background:{C['SURF2']}; }}
.nf {{ text-align:center; margin:10vh 0 1.5rem; }}
.nf-code {{ font-size:72px; font-weight:600; color:{C['MUTED']}; line-height:1; margin-bottom:12px; }}
@media (prefers-reduced-motion: reduce) {{ * {{ transition:none !important; }} }}
@media (max-width:640px) {{
  .block-container {{ padding:1rem 1rem 2rem; }}
  .page-title {{ font-size:20px; }}
  .nf-code {{ font-size:56px; }}
  div[data-testid="stMetricValue"] {{ font-size:22px; }}
  .tbl th, .tbl td {{ padding:8px 10px; }}
}}
</style>""", unsafe_allow_html=True)


# ---------------------------------------------------------------- helpers
@st.cache_data
def logo_html(size):
    if not LOGO.exists():
        return ""
    b64 = base64.b64encode(LOGO.read_bytes()).decode()
    return f'<img class="logo" alt="OMIVIA logo" src="data:image/png;base64,{b64}" width="{size}">'


def space():
    st.markdown('<div style="height:1rem"></div>', unsafe_allow_html=True)


def cols(spec):
    return st.columns(spec, gap="medium")


def header(title, sub):
    st.markdown(f'<div class="page-head"><div class="page-title">{title}</div><div class="page-sub">{sub}</div></div>', unsafe_allow_html=True)


def card(title, sub=""):
    box = st.container(border=True)
    box.markdown(f'<div class="card-title">{title}</div><div class="card-sub">{sub}</div>', unsafe_allow_html=True)
    return box


def style(fig, h=300):
    fig.update_layout(height=h, margin=dict(l=0, r=0, t=10, b=0), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(family=FONT, color=C["MUTED"], size=11),
                      legend=dict(orientation="h", y=1.12, x=1, xanchor="right"), hovermode="x unified",
                      hoverlabel=dict(bgcolor=C["SURF"], font_color=C["TEXT"], bordercolor=C["BORDER"]))
    fig.update_xaxes(showgrid=False, linecolor=C["BORDER"])
    fig.update_yaxes(gridcolor=C["BORDER"], zeroline=False)
    return fig


def table(df, max_rows=300, label="Data table"):
    """Accessible HTML table (real headers, keyboard-scrollable) that follows the active theme."""
    def cell(col, v):
        if col == "Severity":
            return f'<span style="color:{SEV.get(v, C["TEXT"])};font-weight:600">{html.escape(str(v))}</span>'
        if isinstance(v, (bool, np.bool_)):
            return "Yes" if v else "No"
        return html.escape(str(v))
    head = "".join(f'<th scope="col">{html.escape(str(c))}</th>' for c in df.columns)
    body = "".join("<tr>" + "".join(f"<td>{cell(c, v)}</td>" for c, v in zip(df.columns, row)) + "</tr>"
                   for row in df.head(max_rows).itertuples(index=False))
    st.markdown(f'<div class="tbl" role="region" aria-label="{html.escape(label)}" tabindex="0"><table><thead><tr>{head}</tr></thead>'
                f'<tbody>{body}</tbody></table></div>', unsafe_allow_html=True)
    if len(df) > max_rows:
        st.caption(f"Showing the first {max_rows:,} of {len(df):,} rows. Use the filters or export to see the rest.")


@st.dialog("Legal information", width="large")
def show_doc(key):
    st.markdown(legal.DOCS[key])


def footer():
    space()
    st.divider()
    parts = cols([1.2, 1.2, 1.7, 4])
    for col, (k, label) in zip(parts, (("terms", "Terms of Service"), ("privacy", "Privacy Policy"), ("a11y", "Accessibility statement"))):
        if col.button(label, key=f"ft_{k}", type="tertiary"):
            show_doc(k)
    parts[3].caption("OMIVIA detects attacks from account, endpoint and client behavior. The app does not collect or store IP addresses.")


def set_title(title):
    """Sets the browser tab title (Streamlit only supports one static title natively)."""
    try:
        components.html(f"<script>window.parent.document.title = {json.dumps(title)};</script>", height=0)
    except Exception:
        pass


def go_home():
    st.session_state.page = "Overview"
    st.session_state.bad_route = None
    st.query_params.clear()


def not_found(code="404", title="Page not found", msg="That page doesn't exist or has moved. Head back to the Overview to continue."):
    st.markdown(f'<div class="nf" role="alert"><div class="nf-code">{code}</div><div class="page-title">{html.escape(title)}</div>'
                f'<div class="page-sub">{html.escape(msg)}</div></div>', unsafe_allow_html=True)
    _, mid, _ = cols([1.2, 1, 1.2])
    mid.button("Back to Overview", type="primary", width="stretch", on_click=go_home)


# ---------------------------------------------------------------- data
ALIASES = {"timestamp": ["timestamp", "time", "datetime", "date", "event_time", "_time"],
           "username": ["username", "user", "account", "user_name", "userid", "user_id"],
           "result": ["result", "status", "outcome", "success", "event_result"],
           "endpoint": ["endpoint", "url", "path", "app", "service", "resource"],
           "user_agent": ["user_agent", "useragent", "ua", "client", "device"]}


def normalize(df):
    cols = {c.lower().strip(): c for c in df.columns}
    out = pd.DataFrame()
    for key, names in ALIASES.items():
        src = next((cols[n] for n in names if n in cols), None)
        if src is None and key in ("timestamp", "username", "result"):
            raise ValueError(f"missing a '{key}' column (accepted names: {', '.join(names)})")
        out[key] = df[src] if src else "unknown"
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    bad = out["result"].astype(str).str.lower().str.contains("fail|denied|invalid|false|error|^0$")
    out["result"] = np.where(bad, "failure", "success")
    return out.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)


@st.cache_data
def demo_events():
    rng = np.random.default_rng(7)
    t0 = pd.Timestamp.now().floor("h") - pd.Timedelta(hours=24)
    users = "j.smith m.kumar a.rao s.patel r.shah n.verma l.chen d.okafor p.mehta t.nguyen e.silva h.ali k.sato o.novak f.reyes admin svc.backup".split() \
        + [f"emp{i:03d}" for i in range(40)]
    n = 2400
    base = pd.DataFrame({
        "timestamp": t0 + pd.to_timedelta(rng.beta(2.2, 1.8, n) * 1440, unit="m"),
        "username": rng.choice(users, n),
        "result": np.where(rng.random(n) < .05, "failure", "success"),
        "endpoint": rng.choice(["/auth/login", "/vpn/login", "/mail/owa"], n, p=[.5, .3, .2]),
        "user_agent": rng.choice(["Chrome/126 Win", "Safari/17 macOS", "Firefox/127 Linux", "Edge/126 Win"], n)})

    def burst(h, m, names, per, span, ua, ep, win=None):
        s = t0 + pd.Timedelta(hours=h, minutes=m)
        rows = [(s + pd.Timedelta(seconds=float(rng.uniform(0, span * 60))), u, "failure", ep, ua)
                for u in names for _ in range(per)]
        if win:
            rows.append((s + pd.Timedelta(minutes=span + 1), win, "success", ep, ua))
        return pd.DataFrame(rows, columns=base.columns)

    ev = pd.concat([base,
                    burst(14, 0, ["m.kumar"], 46, 9, "Hydra/9.5", "/vpn/login", "m.kumar"),
                    burst(20, 15, ["admin"], 38, 8, "curl/8.4", "/auth/login"),
                    burst(18, 0, users[2:34], 2, 24, "python-requests/2.31", "/auth/login", "s.patel")])
    return ev.sort_values("timestamp").reset_index(drop=True)


def detect(ev, window, bf_min, sp_accts, sp_max):
    """Brute force = depth on one account. Password spray = breadth across accounts from one client fingerprint."""
    f = ev[ev.result == "failure"].copy()
    f["bucket"] = f.timestamp.dt.floor(f"{window}min")
    pad = pd.Timedelta(minutes=window)

    def pick(keys, hit):
        return f[pd.MultiIndex.from_frame(f[keys]).isin(hit)] if len(hit) else f.iloc[0:0]

    rows = []
    g = f.groupby(["bucket", "username"]).size()
    for user, d in pick(["bucket", "username"], g[g >= bf_min].index).groupby("username"):
        a, b = d.timestamp.min(), d.timestamp.max()
        e = ev[(ev.username == user) & (ev.timestamp >= a) & (ev.timestamp <= b + pad)]
        rows.append(dict(type="Brute Force", target=user, failures=len(d), accounts=1, first=a, last=b,
                         client=d.user_agent.mode().iat[0], endpoint=d.endpoint.mode().iat[0], ev=e,
                         why=f"{len(d)} failed logins against one account inside {window}-minute windows (threshold {bf_min}). Depth on a single identity."))
    s = f.groupby(["bucket", "user_agent", "endpoint"]).agg(accts=("username", "nunique"), n=("username", "size"))
    hit = s[(s.accts >= sp_accts) & (s.n / s.accts <= sp_max)].index
    for (ua, ep), d in pick(["bucket", "user_agent", "endpoint"], hit).groupby(["user_agent", "endpoint"]):
        a, b, k = d.timestamp.min(), d.timestamp.max(), d.username.nunique()
        e = ev[(ev.user_agent == ua) & (ev.endpoint == ep) & (ev.timestamp >= a) & (ev.timestamp <= b + pad)]
        rows.append(dict(type="Password Spray", target=f"{k} accounts", failures=len(d), accounts=k, first=a, last=b,
                         client=ua, endpoint=ep, ev=e,
                         why=f"{k} distinct accounts failed from one client fingerprint, at most {sp_max} attempts each (threshold {sp_accts} accounts). Breadth across identities, not depth."))

    cols = ["type", "target", "failures", "accounts", "first", "last", "client", "endpoint", "why", "ev"]
    inc = pd.DataFrame(rows, columns=cols)
    if inc.empty:
        return inc.assign(severity=[], compromise=[], key=[], id=[]).drop(columns="ev"), {}
    inc["compromise"] = inc["ev"].map(lambda e: bool((e.result == "success").any()))
    big = np.where(inc["type"] == "Brute Force", inc["failures"] >= 3 * bf_min, inc["accounts"] >= 2 * sp_accts)
    inc["severity"] = np.where(inc["compromise"] | big, "Critical", "High")
    inc["key"] = inc["type"] + "|" + inc["target"] + "|" + inc["first"].dt.strftime("%H%M")
    inc = inc.sort_values(["severity", "first"], ascending=[True, False]).reset_index(drop=True)
    inc["id"] = [f"INC-{i + 1:03d}" for i in range(len(inc))]
    return inc.drop(columns="ev"), dict(zip(inc["id"], inc["ev"]))


def account_table(ev, inc, evid):
    types, comp = {}, set()
    for _, r in inc.iterrows():
        e = evid[r["id"]]
        for u in e[e.result == "failure"].username.unique():
            types.setdefault(u, set()).add(r["type"])
        comp |= set(e[e.result == "success"].username)
    t = ev[ev.result == "failure"].groupby("username").size().rename("Failed logins").reset_index()
    t.columns = ["Account", "Failed logins"]
    t["Incident type"] = t["Account"].map(lambda u: ", ".join(sorted(types.get(u, []))) or "None")
    t["Privileged"] = t["Account"].str.contains("admin|svc", case=False)
    t["Possible compromise"] = t["Account"].isin(comp) & t["Incident type"].ne("None")
    return t.sort_values(["Possible compromise", "Failed logins"], ascending=False).reset_index(drop=True)


def inc_view(inc):
    return pd.DataFrame({"ID": inc["id"], "Severity": inc["severity"], "Type": inc["type"], "Target": inc["target"],
                         "Failures": inc["failures"], "Accounts": inc["accounts"],
                         "First seen": inc["first"].dt.strftime("%b %d %H:%M"), "Last seen": inc["last"].dt.strftime("%H:%M"),
                         "Possible compromise": inc["compromise"].map({True: "Yes", False: "No"}),
                         "Status": inc["key"].map(lambda k: st.session_state.status.get(k, "New"))})


# ---------------------------------------------------------------- sign in
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]


def start_session(rec):
    st.session_state.update(auth=True, user=rec["name"], email=rec.get("email"), uid=rec.get("uid"),
                            ai_training=rec.get("ai_training", False))


def age_ok(y, m, d):
    try:
        born = date(int(y), MONTHS.index(m) + 1, int(d))
    except (TypeError, ValueError):
        return None
    t = date.today()
    return t.year - born.year - ((t.month, t.day) < (born.month, born.day)) >= store.MIN_AGE


@st.dialog("Sign in to OMIVIA", width="large")
def login():
    t_in, t_new, t_guest = st.tabs(["Sign in", "Create account", "Guest"])
    with t_in:
        email = st.text_input("Email", key="li_email")
        pwd = st.text_input("Password", type="password", key="li_pwd")
        if st.button("Sign in", type="primary", width="stretch", key="li_go"):
            rec = store.authenticate(email, pwd) if email and pwd else None
            if rec:
                start_session(rec)
                st.rerun()
            st.error("That email and password don't match an account.")
    with t_new:
        name = st.text_input("Display name", key="su_name")
        email = st.text_input("Work email", key="su_email")
        c1, c2 = cols(2)
        pwd = c1.text_input("Password (8+ characters)", type="password", key="su_pwd")
        pwd2 = c2.text_input("Confirm password", type="password", key="su_pwd2")
        st.markdown(f"**Date of birth.** Used once to confirm you are {store.MIN_AGE} or over. We don't store it.")
        d1, d2, d3 = cols(3)
        day = d1.selectbox("Day", range(1, 32), index=None, placeholder="Day", key="su_d")
        mon = d2.selectbox("Month", MONTHS, index=None, placeholder="Month", key="su_m")
        yr = d3.selectbox("Year", range(date.today().year, date.today().year - 101, -1), index=None, placeholder="Year", key="su_y")
        with st.expander("Read the Terms of Service"):
            st.markdown(legal.TERMS)
        with st.expander("Read the Privacy Policy"):
            st.markdown(legal.PRIVACY)
        agree = st.checkbox("I have read and accept the Terms of Service and Privacy Policy.", key="su_agree")
        train = st.checkbox("Allow my uploaded logs to be used to train OMIVIA's AI. I can change this any time in Settings.",
                            value=store.AI_TRAINING_DEFAULT, key="su_train")
        if st.button("Create account", type="primary", width="stretch", key="su_go"):
            old = age_ok(yr, mon, day)
            if not name.strip() or "@" not in email:
                st.error("Enter your name and a valid email.")
            elif len(pwd) < 8 or pwd != pwd2:
                st.error("Passwords must match and be at least 8 characters.")
            elif old is None:
                st.error("Enter a valid date of birth.")
            elif not old:
                st.error(f"You must be {store.MIN_AGE} or older to use OMIVIA.")
            elif not agree:
                st.error("Accept the Terms of Service and Privacy Policy to continue.")
            else:
                try:
                    rec = store.create_account(email, name.strip(), pwd, train)
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    start_session(rec)
                    st.rerun()
    with t_guest:
        st.caption("Guests get the full dashboard. Nothing is saved and nothing is used for AI training.")
        ok = st.checkbox(f"I am {store.MIN_AGE} or older and accept the Terms of Service and Privacy Policy.", key="g_ok")
        if st.button("Continue as guest", width="stretch", key="g_go"):
            if ok:
                start_session({"name": "Guest analyst"})
                st.rerun()
            st.error("Please confirm to continue.")


if not st.session_state.auth:
    st.markdown(f'<div style="text-align:center;margin-top:12vh">{logo_html(56)}'
                f'<div class="page-title" style="margin-top:16px">OMIVIA</div>'
                f'<div class="page-sub" style="max-width:420px;margin:6px auto 0">Detect brute force and password spray attacks from identity activity alone.</div></div>',
                unsafe_allow_html=True)
    space()
    _, mid, _ = cols([1.2, 1, 1.2])
    if mid.button("Sign in", type="primary", width="stretch"):
        login()
    set_title("Sign in | OMIVIA")
    footer()
    st.stop()

# ---------------------------------------------------------------- sidebar
_qp = st.query_params.get("page")  # deep links such as ?page=Incidents; unknown values show the 404 page
if _qp and not st.session_state.qp_done:
    st.session_state.qp_done = True
    if _qp in PAGES:
        st.session_state.page = _qp
    else:
        st.session_state.bad_route = (_qp, st.session_state.page)

with st.sidebar:
    st.markdown(f'<div style="display:flex;gap:12px;align-items:center;margin-bottom:24px">{logo_html(42)}'
                f'<div><div class="brand">OMIVIA</div><div class="brand-sub">Login attack detection</div></div></div>',
                unsafe_allow_html=True)
    st.radio("Navigation", PAGES, key="page", label_visibility="collapsed")
    uid = st.session_state.uid
    saved = {f.name: f for f in store.list_uploads(uid)} if uid else {}
    choice = "Demo data"
    with st.expander("Data source"):
        up = st.file_uploader("Authentication log (CSV)", type="csv",
                              help="Needs timestamp, username and result/status columns. Endpoint and user_agent are optional.")
        if saved:
            choice = st.selectbox("Saved logs", ["Demo data"] + list(saved))
        st.caption("Uploads are saved to your account." if uid else "Guest uploads are processed in memory and never saved.")
    ev, source = demo_events(), "Demo data"
    try:
        if up is not None:
            raw = up.getvalue()
            with st.spinner("Reading log file..."):
                ev, source = normalize(pd.read_csv(io.BytesIO(raw))), up.name
            if uid and st.session_state.get("saved_sig") != (up.name, up.size):
                store.save_upload(uid, up.name, raw)
                st.session_state.saved_sig = (up.name, up.size)
        elif choice in saved:
            with st.spinner("Reading saved log..."):
                ev, source = normalize(pd.read_csv(saved[choice])), choice
    except Exception as exc:
        st.error(f"Could not use this file: {exc}")
    st.markdown(f'<div class="chip"><b>Detector running</b><br>{len(ev):,} events from {html.escape(source)}</div>', unsafe_allow_html=True)
    space()
    st.caption(f"Signed in as {st.session_state.user}")
    if st.button("Sign out", width="stretch"):
        st.session_state.update(auth=False, user="", email=None, uid=None, ai_training=False)
        st.rerun()


# ---------------------------------------------------------------- pages
def render(page, R, ev, inc, evid):
    if page == "Overview":
        header("Overview", f"Authentication attacks against identities, {span}")
        acc = account_table(ev, inc, evid)
        k = cols(4)
        k[0].metric("Failed logins", f"{(ev.result == 'failure').sum():,}")
        k[1].metric("Accounts under attack", int((acc["Incident type"] != "None").sum()))
        k[2].metric("Open incidents", len(inc), f"{(inc['severity'] == 'Critical').sum()} critical", delta_color="off")
        k[3].metric("Possible compromises", int(acc["Possible compromise"].sum()))
        space()
        left, right = cols([1.7, 1])
        with left, card("Login activity", "Failed and successful logins per 30 minutes. Shaded bands mark detected attacks."):
            tl = ev.assign(t=ev.timestamp.dt.floor("30min")).groupby(["t", "result"]).size().unstack(fill_value=0)
            fig = go.Figure()
            for res, col in (("success", C["ACCENT"]), ("failure", C["RED"])):
                if res in tl:
                    fig.add_scatter(x=tl.index, y=tl[res], name=res.title(), line=dict(color=col, width=1.75))
            for _, r in inc.iterrows():
                fig.add_vrect(x0=r["first"] - pd.Timedelta(minutes=15), x1=r["last"] + pd.Timedelta(minutes=15),
                              fillcolor=SEV[r["severity"]], opacity=.15, line_width=0)
            st.plotly_chart(style(fig), width="stretch", config={"displayModeBar": False})
        with right, card("Depth versus breadth", "Brute force goes deep on one account. Spray goes wide."):
            fig = go.Figure()
            for t, d in inc.groupby("type"):
                fig.add_scatter(x=d["accounts"], y=d["failures"] / d["accounts"], mode="markers", name=t, text=d["target"],
                                marker=dict(size=d["failures"].clip(14, 46), color=TYPE_COLOR[t], opacity=.85))
            style(fig).update_layout(hovermode="closest", xaxis_title="Accounts targeted", yaxis_title="Failures per account")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        space()
        with card("Priority incidents", "Select the Incidents page for evidence and triage."):
            if inc.empty:
                st.info("No incidents at the current thresholds.")
            else:
                table(inc_view(inc.head(5)), label="Priority incidents")

    elif page == "Incidents":
        header("Incidents", "Triage queue. Select a row to see the evidence behind the detection.")
        if inc.empty:
            st.info("No incidents at the current thresholds. Lower them on the Detection Rules page.")
            return
        table(inc_view(inc), label="Incident queue")
        space()
        names = {i: f"{i}: {t} on {g}" for i, t, g in zip(inc["id"], inc["type"], inc["target"])}
        sel = st.selectbox("Open incident", list(names), format_func=names.get)
        r = inc[inc["id"] == sel].iloc[0]
        e = evid[r["id"]]
        space()
        left, right = cols([1.7, 1])
        with left, card(f"{r['id']}: {r['type']} on {r['target']}", f"{r['first']:%b %d, %H:%M} to {r['last']:%H:%M}"):
            m = e.assign(minute=e.timestamp.dt.floor("min")).groupby(["minute", "result"]).size().unstack(fill_value=0)
            fig = go.Figure()
            for res, col in (("failure", C["RED"]), ("success", C["GREEN"])):
                if res in m:
                    fig.add_bar(x=m.index, y=m[res], name=res.title(), marker_color=col)
            st.plotly_chart(style(fig, 240).update_layout(barmode="stack"), width="stretch", config={"displayModeBar": False})
            if r["compromise"]:
                st.error("A successful login followed the failures. Treat the account(s) as possibly compromised.")
            st.write(r["why"])
            st.caption(f"Client fingerprint: {r['client']}  |  Endpoint: {r['endpoint']}")
        with right, card("Response", "Update status and follow the checklist."):
            cur = st.session_state.status.get(r["key"], "New")
            st.session_state.status[r["key"]] = st.selectbox("Status", STATUSES, index=STATUSES.index(cur), key="sel_" + r["key"])
            steps = (["Lock the account and force a password reset", "Require MFA on the next sign-in", "Review activity after the successful login"]
                     if r["type"] == "Brute Force" else
                     ["Rate-limit or block this client fingerprint", "Force resets on accounts with a later success", "Enable smart lockout on the endpoint"])
            for i, s in enumerate(steps):
                st.checkbox(s, key=f"chk_{r['key']}_{i}")
            st.download_button("Export evidence (CSV)", e.to_csv(index=False), f"{r['id']}_evidence.csv", width="stretch")
        with st.expander("Raw events in this incident"):
            table(e[["timestamp", "username", "result", "endpoint", "user_agent"]], label="Raw events")

    elif page == "Targeted Accounts":
        header("Targeted Accounts", "Accounts ranked by failed logins. Failed-then-succeeded is the strongest compromise signal.")
        acc = account_table(ev, inc, evid)
        only = st.toggle("Only accounts tied to an incident", value=True)
        if only:
            acc = acc[acc["Incident type"] != "None"]
        table(acc.head(50), label="Targeted accounts")

    elif page == "Investigate":
        header("Investigate", "Search raw authentication events by account, endpoint, client and result.")
        a, b, c, d = cols([1.3, 1, 1, 1])
        q = a.text_input("Account contains")
        res = b.multiselect("Result", ["failure", "success"], default=["failure", "success"])
        eps = c.multiselect("Endpoint", sorted(ev.endpoint.unique()))
        uas = d.multiselect("Client fingerprint", sorted(ev.user_agent.unique()))
        v = ev[ev.result.isin(res)]
        if q:
            v = v[v.username.str.contains(q, case=False)]
        if eps:
            v = v[v.endpoint.isin(eps)]
        if uas:
            v = v[v.user_agent.isin(uas)]
        st.caption(f"{len(v):,} matching events")
        table(v.sort_values("timestamp", ascending=False), label="Matching events")
        st.download_button("Export results (CSV)", v.to_csv(index=False), "omivia_events.csv")

    elif page == "Detection Rules":
        header("Detection Rules", "Change a threshold and the detections update immediately.")
        left, right = cols([1, 1.5])
        with left:
            with card("Thresholds", "Applied to the active data source."):
                R["window"] = st.select_slider("Detection window (minutes)", [5, 10, 15, 30, 60], R["window"])
                R["bf_min"] = st.slider("Brute force: failures on one account per window", 5, 100, R["bf_min"])
                R["sp_accts"] = st.slider("Password spray: distinct accounts per window", 5, 100, R["sp_accts"])
                R["sp_max"] = st.slider("Password spray: max failures per account", 1, 10, R["sp_max"])
                if st.button("Reset to defaults", width="stretch"):
                    st.session_state.rules = dict(DEFAULT_RULES)
                    st.rerun()
        inc, evid = detect(ev, **R)
        with right:
            n = cols(3)
            n[0].metric("Incidents", len(inc))
            n[1].metric("Brute force", int((inc["type"] == "Brute Force").sum()))
            n[2].metric("Password spray", int((inc["type"] == "Password Spray").sum()))
            with card("How each rule works"):
                st.markdown(f"**Brute force.** One account collects at least {R['bf_min']} failures inside a {R['window']}-minute window.\n\n"
                            f"**Password spray.** One client fingerprint and endpoint fail against at least {R['sp_accts']} different accounts "
                            f"inside a {R['window']}-minute window, with no more than {R['sp_max']} attempts per account.\n\n"
                            "**Severity.** Critical when a success follows the failures or volume is well above the threshold.")
            if not inc.empty:
                table(inc_view(inc), label="Detected incidents")

    elif page == "Settings":
        header("Settings", "Manage your account, appearance, privacy and data.")
        uid, email = st.session_state.uid, st.session_state.email
        left, right = cols(2)
        with left:
            with card("Account", "Your profile for this workspace."):
                name = st.text_input("Display name", value=st.session_state.user)
                st.text_input("Email", value=email or "Guest session", disabled=True)
                if st.button("Save profile", type="primary", width="stretch"):
                    if name.strip():
                        st.session_state.user = name.strip()
                        if email:
                            store.update(email, name=name.strip())
                        st.rerun()
                    st.error("Display name can't be empty.")
            with card("Appearance", "Applies immediately across the dashboard."):
                theme = st.radio("Theme", ["Dark", "Light"], index=["Dark", "Light"].index(st.session_state.theme), horizontal=True)
                compact = st.toggle("Compact layout", value=st.session_state.compact, help="Tighter page padding to fit more on screen.")
                if theme != st.session_state.theme or compact != st.session_state.compact:
                    st.session_state.theme, st.session_state.compact = theme, compact
                    st.rerun()
            with card("Privacy", "Control how your data is used."):
                train = st.toggle("Use my uploaded logs to train OMIVIA's AI", value=st.session_state.ai_training, disabled=not email)
                if email and train != st.session_state.ai_training:
                    store.update(email, ai_training=train)
                    st.session_state.ai_training = train
                    st.toast("AI training is on." if train else "AI training is off. Your files are excluded from future training.")
                if email:
                    st.caption(f"{len(store.list_uploads(uid)) if train else 0} of your saved files are currently eligible for training.")
                else:
                    st.caption("Guest data is never stored or used for training.")
                a, b = cols(2)
                if a.button("Privacy Policy", key="s_priv", width="stretch"):
                    show_doc("privacy")
                if b.button("Terms of Service", key="s_terms", width="stretch"):
                    show_doc("terms")
        with right:
            with card("Notifications", "Pop-up alerts while you work."):
                st.session_state.notify = st.toggle("Alert me about new critical incidents", value=st.session_state.notify)
            with card("Your data", "Stored on this server until you delete it."):
                files = store.list_uploads(uid) if uid else []
                if files:
                    table(pd.DataFrame({"File": [f.name for f in files], "Size (KB)": [round(f.stat().st_size / 1024, 1) for f in files]}), label="Saved files")
                else:
                    st.caption("No saved log files." if uid else "Guest uploads are processed in memory and never saved.")
                a, b = cols(2)
                if a.button("Reset detection rules", width="stretch"):
                    st.session_state.rules = dict(DEFAULT_RULES)
                    st.toast("Detection rules reset to defaults.")
                if b.button("Clear incident statuses", width="stretch"):
                    st.session_state.status = {}
                    st.toast("Incident statuses cleared.")
                if files and st.button("Delete my saved log files", width="stretch"):
                    store.delete_uploads(uid)
                    st.rerun()
            with card("Delete account", "Permanently removes your login, saved log files and preferences."):
                if not email:
                    st.caption("Guest sessions have no account. Signing out clears everything.")
                else:
                    st.caption("This can't be undone. Your account record, password hash, uploaded files and settings are erased from storage immediately.")
                    pw = st.text_input("Password", type="password", key="del_pw")
                    confirm = st.text_input("Type DELETE to confirm", key="del_confirm")
                    if st.button("Delete account permanently", disabled=confirm != "DELETE" or not pw, width="stretch"):
                        if store.authenticate(email, pw):
                            store.delete_account(email, uid)
                            st.session_state.clear()
                            st.rerun()
                        st.error("Password is incorrect.")


# ---------------------------------------------------------------- dispatch
page, R = st.session_state.page, st.session_state.rules
try:
    inc, evid = detect(ev, **R)
except Exception:
    traceback.print_exc()
    not_found("Error", "We couldn't read that data", "The file doesn't look like authentication logs. Remove it from Data source and try again.")
    footer()
    st.stop()
span = f"{ev.timestamp.min():%b %d, %H:%M} to {ev.timestamp.max():%b %d, %H:%M}"

if st.session_state.notify:
    for _, r in inc[inc["severity"] == "Critical"].iterrows():
        if r["key"] not in st.session_state.notified:
            st.session_state.notified.append(r["key"])
            st.toast(f"{r['id']}: {r['type']} on {r['target']}")

bad = st.session_state.bad_route
if bad and page == bad[1]:
    set_title("Page not found | OMIVIA")
    not_found()
else:
    set_title(f"{page} | OMIVIA")
    try:
        render(page, R, ev, inc, evid)
    except Exception:
        traceback.print_exc()
        not_found("Error", "Something went wrong", "This page hit an unexpected problem. Your data is safe. Head back to the Overview to continue.")
footer()