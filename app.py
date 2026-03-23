import streamlit as st
import pandas as pd
import joblib,re,tldextract
from urllib.parse import urlparse
from difflib import SequenceMatcher

# ======================================================
# PAGE CONFIG
# ======================================================

st.set_page_config(
page_title="PhishGuard SOC Dashboard",
page_icon="🛡",
layout="wide"
)

# ======================================================
# SESSION STATE
# ======================================================

if "batch_results" not in st.session_state:
    st.session_state.batch_results=None
if "batch_evidence" not in st.session_state:
    st.session_state.batch_evidence=None
if "batch_run" not in st.session_state:
    st.session_state.batch_run=False

# ======================================================
# LOAD MODELS (Cached)
# ======================================================

@st.cache_resource
def load_models():
    return(
    joblib.load("models_new/tfidf.pkl"),
    joblib.load("models_new/logistic.pkl"),
    joblib.load("models_new/rf.pkl"),
    joblib.load("models_new/xgb.pkl"),
    joblib.load("models_new/thresholds.pkl")
    )

tfidf,logistic,rf,xgb,thresholds=load_models()

# Warm PSL cache
tldextract.extract("google.com")

DEFAULT_THRESHOLDS={
"Logistic Regression":thresholds["log_th"],
"Random Forest":thresholds["rf_th"],
"XGBoost":thresholds["xgb_th"]
}

# ======================================================
# SIDEBAR CONTROLS
# ======================================================

st.sidebar.header("SOC Controls")

model_mode=st.sidebar.selectbox(
"Select Detection Model",
["Logistic Regression","Random Forest","XGBoost"]
)

threshold=st.sidebar.slider(
f"Active Threshold → {model_mode}",
0.0,1.0,
float(DEFAULT_THRESHOLDS[model_mode]),
0.01
)

# ======================================================
# FEATURE CONFIG
# ======================================================

BRANDS=["google","facebook","amazon","microsoft","apple",
"paypal","netflix","instagram","linkedin","twitter"]

RISKY_TLDS={"tk","ml","ga","cf","gq"}

KEYWORDS=["login","verify","secure","account",
"update","bank","confirm","signin"]

BRAND_ALERT_TH=0.8

# ======================================================
# FEATURE EXTRACTION
# ======================================================

def brand_similarity(domain):
    best=0
    for b in BRANDS:
        best=max(best,
        SequenceMatcher(None,domain,b).ratio())
    return best

def keyword_score(url):
    url=url.lower()
    return sum(k in url for k in KEYWORDS)

def is_ip(domain):
    return int(bool(
    re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$",domain)
    ))

def extract_features(url):

    parsed=urlparse(url)
    ext=tldextract.extract(url)
    subdomain=ext.subdomain

    feats={
    "url_length":len(url),
    "num_dots":url.count("."),
    "num_hyphens":url.count("-"),
    "num_digits":sum(c.isdigit() for c in url),
    "has_https_token":int("https" in parsed.path.lower()),
    "is_ip":is_ip(parsed.netloc),
    "keyword_score":keyword_score(url),
    "brand_similarity":brand_similarity(ext.domain),
    "risky_tld":int(ext.suffix in RISKY_TLDS),
    "subdomain_count":
    0 if subdomain=="" else subdomain.count(".")+1
    }

    return pd.DataFrame([feats]),ext

# ======================================================
# INFERENCE
# ======================================================

def get_probs(url):

    X=tfidf.transform([url])
    log_p=logistic.predict_proba(X)[0][1]

    struct,ext=extract_features(url)

    rf_p=rf.predict_proba(struct)[0][1]
    xgb_p=xgb.predict_proba(struct)[0][1]

    return log_p,rf_p,xgb_p,struct.iloc[0],ext

@st.cache_data(show_spinner=False)
def cached_probs(url):
    return get_probs(url)

def active_score(lp,rfp,xp):

    prob={
    "Logistic Regression":lp,
    "Random Forest":rfp,
    "XGBoost":xp
    }[model_mode]

    return prob,int(prob>=threshold)

def verdict_label(pred):
    return "⚠ Phishing" if pred else "✅ Legitimate"

# ======================================================
# UI
# ======================================================

st.title("🛡 SOC Phishing Detection System")

single_tab,batch_tab=st.tabs([
"🔎 Single URL Investigation",
"📂 Batch Investigation"
])

# ================= SINGLE URL =================

with single_tab:

    st.subheader("Single URL Investigation")

    with st.form("single_form"):
        url=st.text_input("Enter URL")
        analyse=st.form_submit_button("Analyse URL")

    if analyse:

        if not url.strip():
            st.warning("Enter URL.")
        else:

            lp,rfp,xp,struct,ext=get_probs(url)
            score,pred=active_score(lp,rfp,xp)

            st.write(
            f"Active Model → **{model_mode}** | "
            f"Threshold → **{threshold:.3f}"
            )

            (st.error if pred else st.success)(
            f"{verdict_label(pred)}\n\nConfidence → {score:.3f}"
            )

            st.dataframe(pd.DataFrame({

            "Model":["Logistic","Random Forest","XGBoost"],

            "Probability":[
            round(lp,3),
            round(rfp,3),
            round(xp,3)]

            }),width="stretch")

            st.json({

            "Domain":ext.domain,
            "TLD":ext.suffix,
            "Subdomains":struct["subdomain_count"],
            "Digits":struct["num_digits"],
            "Risky TLD":
            "Yes" if struct["risky_tld"] else "No",
            "Keyword Score":
            struct["keyword_score"]

            })

# ================= BATCH =================

with batch_tab:

    st.subheader("Batch Investigation")

    uploaded=st.file_uploader(
    "Upload CSV with column 'url'",
    type=["csv"]
    )

    start=st.button("Start Batch Scan")

    if uploaded and start:
        st.session_state.batch_run=True

    if uploaded and st.session_state.batch_run:

        df=pd.read_csv(uploaded)

        if "url" not in df.columns:
            st.error("CSV must contain 'url'.")
        else:

            df=df.dropna(subset=["url"]).drop_duplicates(subset=["url"])

            results=[]
            evidence={"keyword":0,"risky":0,"brand":0,"ip":0}

            progress=st.progress(0)
            status=st.empty()

            total=len(df)

            for i,u in enumerate(df["url"]):

                status.text(f"Scanning {i+1}/{total}")

                lp,rfp,xp,struct,_=cached_probs(str(u))
                score,pred=active_score(lp,rfp,xp)

                if struct["keyword_score"]>0: evidence["keyword"]+=1
                if struct["risky_tld"]: evidence["risky"]+=1
                if struct["brand_similarity"]>BRAND_ALERT_TH: evidence["brand"]+=1
                if struct["is_ip"]: evidence["ip"]+=1

                results.append({

                "url":u,
                "logistic_prob":lp,
                "rf_prob":rfp,
                "xgb_prob":xp,
                "active_model":model_mode,
                "active_threshold":threshold,
                "active_score":score,
                "prediction":pred,
                "verdict":verdict_label(pred)

                })

                progress.progress((i+1)/total)

            st.session_state.batch_results=pd.DataFrame(results)
            st.session_state.batch_evidence=evidence
            st.session_state.batch_run=False

    if isinstance(st.session_state.batch_results,pd.DataFrame):

        res=st.session_state.batch_results
        evidence=st.session_state.batch_evidence

        phishing=int(res["prediction"].sum())
        legit=len(res)-phishing

        col1,col2,col3,col4,col5=st.columns(5)

        col1.metric("Total",len(res))
        col2.metric("Phishing",phishing)
        col3.metric("Legitimate",legit)
        col4.metric("Model",model_mode)
        col5.metric("Threshold",f"{threshold:.3f}")

        filt=st.selectbox(
        "Show",
        ["All","Phishing Only","Legitimate Only"]
        )

        show=res.copy()

        if filt=="Phishing Only":
            show=show[show.prediction==1]
        elif filt=="Legitimate Only":
            show=show[show.prediction==0]

        display=show.copy()

        for c in [
        "logistic_prob","rf_prob",
        "xgb_prob","active_score"]:
            display[c]=display[c].round(3)

        st.dataframe(display,width="stretch")

        st.download_button(
        "Download Investigation Report",
        res.to_csv(index=False).encode("utf-8"),
        "soc_scan_results.csv",
        "text/csv"
        )