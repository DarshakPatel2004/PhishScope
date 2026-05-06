import streamlit as st
import pandas as pd
import numpy as np
import joblib, re, tldextract
from urllib.parse import urlparse
from difflib import SequenceMatcher

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="PhishScope // SOC Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ======================================================
# GLOBAL STYLES  ── Premium Black-Ops Cyber Warfare Terminal
# ======================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,300;0,400;0,600;1,300&family=Barlow+Condensed:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

/* ─── DESIGN TOKENS ─────────────────────────────────── */
:root {
    --bg:           #050709;
    --bg-deep:      #030405;
    --bg-panel:     #080b0f;
    --bg-card:      #0c1018;
    --bg-card-hi:   #111820;
    --border:       #161e28;
    --border-hi:    #1f2d3d;
    --border-glow:  #2a4060;
    --amber:        #f0a500;
    --amber-bright: #ffbe33;
    --amber-dim:    #8a5c00;
    --amber-ghost:  rgba(240,165,0,0.07);
    --red:          #ff2d55;
    --red-dim:      rgba(255,45,85,0.12);
    --red-border:   rgba(255,45,85,0.4);
    --green:        #00e676;
    --green-dim:    rgba(0,230,118,0.08);
    --green-border: rgba(0,230,118,0.3);
    --blue:         #00b4ff;
    --blue-dim:     rgba(0,180,255,0.06);
    --muted:        #3a4a5c;
    --muted-hi:     #5a6e84;
    --text:         #8fa4bc;
    --text-hi:      #c8daea;
    --text-max:     #e8f0f8;
    --mono:         'IBM Plex Mono', monospace;
    --cond:         'Barlow Condensed', sans-serif;
    --display:      'Orbitron', sans-serif;
    --radius:       3px;
}

/* ─── GLOBAL RESET ──────────────────────────────────── */
html, body, [class*="css"], .stApp {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--mono) !important;
}

/* ─── HEX GRID ATMOSPHERE ───────────────────────────── */
.main::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
        radial-gradient(circle at 20% 50%, rgba(0,180,255,0.025) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(240,165,0,0.03) 0%, transparent 50%),
        url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='52'%3E%3Cpath d='M30 2 L58 17 L58 35 L30 50 L2 35 L2 17 Z' fill='none' stroke='%23111820' stroke-width='0.5'/%3E%3C/svg%3E");
    background-size: auto, auto, 60px 52px;
    pointer-events: none;
    z-index: 0;
}

/* ─── SCANLINES ─────────────────────────────────────── */
.main::after {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 3px,
        rgba(0,0,0,0.06) 3px,
        rgba(0,0,0,0.06) 4px
    );
    pointer-events: none;
    z-index: 9999;
    mix-blend-mode: multiply;
}

/* ─── SIDEBAR ───────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: var(--bg-panel) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] > div:first-child {
    background: transparent !important;
    padding: 0 !important;
}
[data-testid="stSidebar"] * {
    font-family: var(--mono) !important;
}
[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stSlider label,
[data-testid="stSidebar"] .stFileUploader label {
    color: var(--amber) !important;
    font-size: 0.6rem !important;
    letter-spacing: 0.16em !important;
    text-transform: uppercase !important;
}
[data-testid="stSidebar"] .stSelectbox > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    color: var(--text-hi) !important;
    font-size: 0.78rem !important;
}
[data-testid="stSidebar"] .stSlider [data-baseweb="slider"] div[role="slider"] {
    background: var(--amber) !important;
    border-color: var(--amber) !important;
    box-shadow: 0 0 10px rgba(240,165,0,0.5) !important;
}
[data-testid="stSidebar"] .stSlider [data-baseweb="slider"] div[data-testid="stSliderTrackFill"] {
    background: linear-gradient(90deg, var(--amber-dim), var(--amber)) !important;
}

/* ─── MAIN LAYOUT ───────────────────────────────────── */
.main .block-container {
    padding: 0 2rem 3rem !important;
    max-width: 1440px !important;
    position: relative;
    z-index: 1;
}

/* ─── TABS ──────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    color: var(--muted) !important;
    font-family: var(--mono) !important;
    font-size: 0.68rem !important;
    letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
    padding: 0.8rem 1.8rem !important;
    transition: all 0.25s !important;
}
.stTabs [data-baseweb="tab"]:hover {
    color: var(--text) !important;
    background: rgba(255,255,255,0.02) !important;
}
.stTabs [aria-selected="true"] {
    color: var(--amber) !important;
    border-bottom-color: var(--amber) !important;
    text-shadow: 0 0 20px rgba(240,165,0,0.5) !important;
}
.stTabs [data-baseweb="tab-panel"] {
    padding-top: 1.8rem !important;
}

/* ─── TEXT INPUT ────────────────────────────────────── */
.stTextInput > div > div > input {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    color: var(--text-hi) !important;
    font-family: var(--mono) !important;
    font-size: 0.85rem !important;
    padding: 0.75rem 1rem !important;
    transition: all 0.2s !important;
    letter-spacing: 0.02em !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--amber) !important;
    box-shadow: 0 0 0 2px rgba(240,165,0,0.12), 0 0 20px rgba(240,165,0,0.08) !important;
}
.stTextInput > div > div > input::placeholder {
    color: var(--muted) !important;
    font-size: 0.78rem !important;
}
.stTextInput label {
    color: var(--amber) !important;
    font-family: var(--mono) !important;
    font-size: 0.6rem !important;
    letter-spacing: 0.16em !important;
    text-transform: uppercase !important;
}

/* ─── BUTTONS ───────────────────────────────────────── */
.stButton > button,
[data-testid="stFormSubmitButton"] > button {
    background: transparent !important;
    border: 1px solid var(--amber) !important;
    border-radius: var(--radius) !important;
    color: var(--amber) !important;
    font-family: var(--mono) !important;
    font-size: 0.68rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.16em !important;
    text-transform: uppercase !important;
    padding: 0.6rem 1.8rem !important;
    cursor: pointer !important;
    transition: all 0.2s !important;
    position: relative !important;
    overflow: hidden !important;
}
.stButton > button::before,
[data-testid="stFormSubmitButton"] > button::before {
    content: '' !important;
    position: absolute !important;
    inset: 0 !important;
    background: linear-gradient(135deg, transparent 40%, rgba(240,165,0,0.08) 100%) !important;
    opacity: 0 !important;
    transition: opacity 0.2s !important;
}
.stButton > button:hover,
[data-testid="stFormSubmitButton"] > button:hover {
    background: rgba(240,165,0,0.08) !important;
    box-shadow: 0 0 20px rgba(240,165,0,0.2), inset 0 0 20px rgba(240,165,0,0.04) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:hover::before,
[data-testid="stFormSubmitButton"] > button:hover::before {
    opacity: 1 !important;
}

/* ─── METRICS ───────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-top: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    padding: 1.1rem 1.3rem !important;
    position: relative !important;
    overflow: hidden !important;
    transition: border-color 0.2s !important;
}
[data-testid="stMetric"]::before {
    content: '' !important;
    position: absolute !important;
    top: 0; left: 0; right: 0 !important;
    height: 1px !important;
    background: linear-gradient(90deg, transparent, var(--amber), transparent) !important;
}
[data-testid="stMetric"]::after {
    content: '' !important;
    position: absolute !important;
    top: 0; left: 0; bottom: 0 !important;
    width: 2px !important;
    background: linear-gradient(180deg, var(--amber), transparent) !important;
    opacity: 0.6 !important;
}
[data-testid="stMetricLabel"] > div {
    color: var(--muted-hi) !important;
    font-family: var(--mono) !important;
    font-size: 0.58rem !important;
    letter-spacing: 0.18em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] > div {
    color: var(--text-max) !important;
    font-family: var(--display) !important;
    font-size: 1.7rem !important;
    letter-spacing: 0.05em !important;
    text-shadow: 0 0 30px rgba(240,165,0,0.15) !important;
}

/* ─── DATAFRAME ─────────────────────────────────────── */
.stDataFrame {
    border: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    overflow: hidden !important;
}
.stDataFrame thead th {
    background: var(--bg-card-hi) !important;
    color: var(--amber) !important;
    font-family: var(--mono) !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid var(--border-hi) !important;
}
.stDataFrame tbody td {
    font-family: var(--mono) !important;
    font-size: 0.75rem !important;
    color: var(--text) !important;
    border-bottom: 1px solid var(--border) !important;
}

/* ─── SELECTBOX ─────────────────────────────────────── */
.stSelectbox > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
    color: var(--text-hi) !important;
}
.stSelectbox label {
    color: var(--amber) !important;
    font-family: var(--mono) !important;
    font-size: 0.6rem !important;
    letter-spacing: 0.14em !important;
    text-transform: uppercase !important;
}

/* ─── PROGRESS BAR ──────────────────────────────────── */
.stProgress > div > div > div {
    background: var(--border-hi) !important;
    border-radius: 1px !important;
}
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, var(--amber-dim), var(--amber)) !important;
    border-radius: 1px !important;
    box-shadow: 0 0 10px rgba(240,165,0,0.4) !important;
    transition: width 0.1s linear !important;
}

/* ─── FILE UPLOADER ─────────────────────────────────── */
[data-testid="stFileUploader"] {
    background: var(--bg-card) !important;
    border: 1px dashed var(--border-hi) !important;
    border-radius: var(--radius) !important;
    transition: border-color 0.2s !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: var(--amber-dim) !important;
}
[data-testid="stFileUploader"] label {
    color: var(--text) !important;
    font-family: var(--mono) !important;
    font-size: 0.72rem !important;
}

/* ─── DOWNLOAD BUTTON ───────────────────────────────── */
[data-testid="stDownloadButton"] > button {
    background: transparent !important;
    border: 1px solid var(--border-hi) !important;
    border-radius: var(--radius) !important;
    color: var(--muted-hi) !important;
    font-family: var(--mono) !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: var(--amber) !important;
    color: var(--amber) !important;
    background: var(--amber-ghost) !important;
}

/* ─── HEADINGS ──────────────────────────────────────── */
h1, h2, h3 {
    font-family: var(--display) !important;
    color: var(--text-max) !important;
    letter-spacing: 0.06em !important;
}
h4, h5, h6 {
    font-family: var(--mono) !important;
    color: var(--muted) !important;
    font-size: 0.62rem !important;
    letter-spacing: 0.16em !important;
    text-transform: uppercase !important;
    font-weight: 400 !important;
}

/* ─── ALERTS ────────────────────────────────────────── */
.stAlert, [data-testid="stAlert"] {
    border-radius: var(--radius) !important;
    font-family: var(--mono) !important;
    font-size: 0.75rem !important;
}
[data-baseweb="notification"] {
    background: rgba(255,200,0,0.06) !important;
    border-left: 3px solid var(--amber) !important;
}

/* ─────────────────────────────────────────────────────
   CUSTOM COMPONENT STYLES
   ───────────────────────────────────────────────────── */

/* ── MASTER HEADER ── */
.pg-header {
    padding: 2rem 0 1.8rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    position: relative;
}
.pg-header::after {
    content: '';
    position: absolute;
    bottom: -1px; left: 0;
    width: 220px; height: 1px;
    background: linear-gradient(90deg, var(--amber), transparent);
}
.pg-wordmark {
    font-family: var(--display);
    font-size: 2.6rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    line-height: 1;
    color: var(--text-max);
    position: relative;
}
.pg-wordmark em {
    color: var(--amber);
    font-style: normal;
}
/* glitch animation */
.pg-wordmark::before,
.pg-wordmark::after {
    content: 'PHISHSCOPE';
    position: absolute;
    top: 0; left: 0;
    font-family: var(--display);
    font-size: 2.6rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    opacity: 0;
}
.pg-wordmark::before {
    color: var(--red);
    animation: glitch-r 4s 1s infinite;
    clip-path: polygon(0 30%, 100% 30%, 100% 50%, 0 50%);
}
.pg-wordmark::after {
    color: var(--blue);
    animation: glitch-b 4s 1.1s infinite;
    clip-path: polygon(0 55%, 100% 55%, 100% 70%, 0 70%);
}
@keyframes glitch-r {
    0%, 92%, 100% { opacity: 0; transform: none; }
    93%            { opacity: 0.7; transform: translateX(-3px); }
    95%            { opacity: 0.5; transform: translateX(3px); }
    97%            { opacity: 0; }
}
@keyframes glitch-b {
    0%, 93%, 100% { opacity: 0; transform: none; }
    94%            { opacity: 0.6; transform: translateX(4px); }
    96%            { opacity: 0.4; transform: translateX(-2px); }
    98%            { opacity: 0; }
}

.pg-meta {
    margin-top: 0.4rem;
    display: flex;
    align-items: center;
    gap: 1rem;
}
.pg-tagline {
    font-family: var(--mono);
    font-size: 0.6rem;
    color: var(--muted);
    letter-spacing: 0.16em;
    text-transform: uppercase;
}
.pg-sep { color: var(--border-hi); }

.pg-right {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.6rem;
}
.pg-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-family: var(--mono);
    font-size: 0.6rem;
    color: var(--green);
    letter-spacing: 0.14em;
    text-transform: uppercase;
}
.pg-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green), 0 0 16px rgba(0,230,118,0.4);
    animation: dot-pulse 2.5s ease-in-out infinite;
}
@keyframes dot-pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 8px var(--green), 0 0 16px rgba(0,230,118,0.4); }
    50% { opacity: 0.5; box-shadow: 0 0 4px var(--green); }
}
.pg-corpus {
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    letter-spacing: 0.12em;
    text-transform: uppercase;
}

/* ── SECTION LABEL ── */
.sect {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    font-family: var(--mono);
    font-size: 0.58rem;
    color: var(--muted-hi);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.9rem;
}
.sect::before {
    content: '';
    display: inline-block;
    width: 12px; height: 1px;
    background: var(--amber);
    flex-shrink: 0;
}

/* ── VERDICT CARDS ── */
.verdict-wrap {
    border-radius: var(--radius);
    padding: 1.4rem 1.6rem;
    margin: 0.6rem 0 1.2rem;
    font-family: var(--mono);
    position: relative;
    overflow: hidden;
    animation: verdict-in 0.35s ease forwards;
}
@keyframes verdict-in {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: none; }
}
.verdict-wrap::before {
    content: '';
    position: absolute;
    inset: 0;
    background: inherit;
    z-index: -1;
}

.verdict-phish {
    background: var(--red-dim);
    border: 1px solid var(--red-border);
    border-left: 3px solid var(--red);
}
.verdict-phish::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, var(--red), transparent);
}

.verdict-safe {
    background: var(--green-dim);
    border: 1px solid var(--green-border);
    border-left: 3px solid var(--green);
}
.verdict-safe::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, var(--green), transparent);
}

.v-eyebrow {
    font-size: 0.55rem;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
    opacity: 0.6;
}
.v-eyebrow.phish { color: var(--red); }
.v-eyebrow.safe  { color: var(--green); }

.v-label {
    font-family: var(--display);
    font-size: 1.5rem;
    letter-spacing: 0.08em;
    line-height: 1;
    margin-bottom: 0.7rem;
}
.v-label.phish { color: var(--red); text-shadow: 0 0 30px rgba(255,45,85,0.4); }
.v-label.safe  { color: var(--green); text-shadow: 0 0 30px rgba(0,230,118,0.3); }

.v-meta {
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
}
.v-pill {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
}
.v-pill-label {
    font-size: 0.52rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--muted);
}
.v-pill-val {
    font-size: 0.85rem;
    color: var(--text-hi);
}

/* ── THREAT BAR ── */
.threat-bar-wrap {
    margin: 1rem 0 0;
}
.threat-bar-track {
    height: 3px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
    margin-top: 0.4rem;
}
.threat-bar-fill-phish {
    height: 100%;
    background: linear-gradient(90deg, #8b0000, var(--red));
    border-radius: 2px;
    box-shadow: 0 0 8px rgba(255,45,85,0.6);
    animation: bar-in 0.6s 0.2s cubic-bezier(0.16,1,0.3,1) both;
}
.threat-bar-fill-safe {
    height: 100%;
    background: linear-gradient(90deg, #003d20, var(--green));
    border-radius: 2px;
    box-shadow: 0 0 8px rgba(0,230,118,0.5);
    animation: bar-in 0.6s 0.2s cubic-bezier(0.16,1,0.3,1) both;
}
@keyframes bar-in {
    from { width: 0 !important; }
}

/* ── MODEL BREAKDOWN ── */
.model-row {
    display: flex;
    align-items: center;
    padding: 0.6rem 0;
    border-bottom: 1px solid var(--border);
    gap: 0.8rem;
}
.model-row:last-child { border-bottom: none; }
.model-name {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted-hi);
    letter-spacing: 0.06em;
    min-width: 130px;
}
.model-active-mark {
    font-size: 0.5rem;
    color: var(--amber);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border: 1px solid var(--amber-dim);
    padding: 0.05rem 0.35rem;
    border-radius: 2px;
    background: var(--amber-ghost);
    margin-left: 0.4rem;
}
.model-track {
    flex: 1;
    height: 3px;
    background: var(--border-hi);
    border-radius: 2px;
    overflow: hidden;
}
.model-fill {
    height: 100%;
    border-radius: 2px;
}
.model-val {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--text-hi);
    min-width: 44px;
    text-align: right;
}

/* ── FEATURE GRID ── */
.feat-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.55rem;
}
.feat-cell {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.65rem 0.8rem;
    transition: border-color 0.15s;
}
.feat-cell:hover { border-color: var(--border-glow); }
.feat-key {
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    letter-spacing: 0.16em;
    text-transform: uppercase;
    margin-bottom: 0.2rem;
}
.feat-val {
    font-family: var(--display);
    font-size: 0.95rem;
    color: var(--text-hi);
    letter-spacing: 0.03em;
}
.feat-val.warn { color: var(--red); text-shadow: 0 0 12px rgba(255,45,85,0.4); }
.feat-val.ok   { color: var(--green); }
.feat-val.note { color: var(--amber); }

/* ── EVIDENCE ROWS ── */
.evidence-row {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.65rem 0;
    border-bottom: 1px solid var(--border);
}
.evidence-row:last-child { border-bottom: none; }
.evidence-chip {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--amber);
    background: var(--amber-ghost);
    border: 1px solid var(--amber-dim);
    border-radius: 2px;
    padding: 0.15rem 0.6rem;
    min-width: 36px;
    text-align: center;
    font-weight: 600;
}
.evidence-chip.zero {
    color: var(--muted);
    background: transparent;
    border-color: var(--border);
}
.ev-label {
    font-family: var(--mono);
    font-size: 0.73rem;
    color: var(--text);
}
.ev-desc {
    font-size: 0.58rem;
    color: var(--muted);
    letter-spacing: 0.06em;
    margin-top: 0.1rem;
}

/* ── SIDEBAR COMPONENTS ── */
.sb-head {
    background: linear-gradient(180deg, rgba(240,165,0,0.04) 0%, transparent 100%);
    border-bottom: 1px solid var(--border);
    padding: 1.2rem 1rem 1rem;
    margin-bottom: 0.5rem;
}
.sb-logo {
    font-family: var(--display);
    font-size: 1.3rem;
    color: var(--amber);
    letter-spacing: 0.12em;
    line-height: 1;
}
.sb-logo span { color: var(--text-hi); }
.sb-sub {
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    letter-spacing: 0.16em;
    text-transform: uppercase;
    margin-top: 0.25rem;
}

.sb-config {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.8rem;
    margin-top: 0.5rem;
}
.sb-cfg-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.3rem 0;
    font-family: var(--mono);
    font-size: 0.68rem;
}
.sb-cfg-key { color: var(--muted-hi); }
.sb-cfg-val { color: var(--amber); font-weight: 600; }
.sb-divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 0.9rem 0;
}
.sb-info {
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    line-height: 2.1;
}
.sb-info-dot {
    display: inline-block;
    width: 4px; height: 4px;
    border-radius: 50%;
    background: var(--amber-dim);
    margin-right: 0.4rem;
    vertical-align: middle;
}

/* ── BATCH METRICS ROW ── */
.batch-metric-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 0.7rem;
    margin-bottom: 1.2rem;
}

/* ── SCAN STATUS ── */
.scan-status {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted-hi);
    letter-spacing: 0.1em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.4rem 0;
}
.scan-spinner {
    width: 8px; height: 8px;
    border: 1px solid var(--border-hi);
    border-top-color: var(--amber);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── RESULT TABLE VERDICT COLORS ── */
[data-testid="stDataFrame"] [aria-selected="false"] td:last-child {
    font-family: var(--mono) !important;
}

/* ── GLOBAL FADE-IN ── */
@keyframes fade-up {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: none; }
}
.main .block-container > div > div {
    animation: fade-up 0.4s ease both;
}

/* ── VOTE BADGES ── */
.vote-badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 0.5rem;
    font-weight: 600;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    padding: 0.1rem 0.5rem;
    border-radius: 2px;
    margin-left: 0.6rem;
    vertical-align: middle;
}
.vote-badge-phish {
    color: var(--red);
    background: var(--red-dim);
    border: 1px solid var(--red-border);
}
.vote-badge-safe {
    color: var(--green);
    background: var(--green-dim);
    border: 1px solid var(--green-border);
}

/* ── ENSEMBLE METER (3 dots) ── */
.ensemble-meter {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    margin: 0.5rem 0;
}
.em-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    border: 1px solid var(--border-hi);
    background: var(--bg-card);
    transition: all 0.3s;
}
.em-dot.active-phish {
    background: var(--red);
    border-color: var(--red);
    box-shadow: 0 0 8px rgba(255,45,85,0.6);
}
.em-dot.active-safe {
    background: var(--green);
    border-color: var(--green);
    box-shadow: 0 0 8px rgba(0,230,118,0.5);
}
.em-label {
    font-family: var(--mono);
    font-size: 0.6rem;
    color: var(--muted-hi);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-left: 0.4rem;
}

/* ── CONFIDENCE TIERS ── */
.conf-tier {
    display: inline-block;
    font-family: var(--display);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.2rem 0.8rem;
    border-radius: 2px;
    margin-left: 0.6rem;
}
.tier-critical {
    color: #ff1744;
    background: rgba(255,23,68,0.12);
    border: 1px solid rgba(255,23,68,0.4);
    text-shadow: 0 0 12px rgba(255,23,68,0.5);
}
.tier-probable {
    color: #ff9100;
    background: rgba(255,145,0,0.10);
    border: 1px solid rgba(255,145,0,0.35);
    text-shadow: 0 0 12px rgba(255,145,0,0.4);
}
.tier-low {
    color: #ffd600;
    background: rgba(255,214,0,0.08);
    border: 1px solid rgba(255,214,0,0.3);
}
.tier-clear {
    color: var(--green);
    background: var(--green-dim);
    border: 1px solid var(--green-border);
    text-shadow: 0 0 10px rgba(0,230,118,0.3);
}

/* ── DISAGREEMENT ALERT ── */
.disagree-alert {
    background: rgba(240,165,0,0.06);
    border: 1px solid rgba(240,165,0,0.25);
    border-left: 3px solid var(--amber);
    border-radius: var(--radius);
    padding: 0.8rem 1.2rem;
    margin: 0.8rem 0;
    font-family: var(--mono);
    animation: verdict-in 0.35s ease forwards;
}
.disagree-alert .da-title {
    font-size: 0.6rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--amber);
    margin-bottom: 0.4rem;
    font-weight: 600;
}
.disagree-alert .da-body {
    font-size: 0.72rem;
    color: var(--text);
    line-height: 1.7;
}
.da-model-tag {
    display: inline-block;
    font-size: 0.58rem;
    letter-spacing: 0.1em;
    padding: 0.08rem 0.45rem;
    border-radius: 2px;
    margin: 0 0.2rem;
    font-weight: 600;
}
.da-model-tag.dissent-phish {
    color: var(--red);
    background: var(--red-dim);
    border: 1px solid var(--red-border);
}
.da-model-tag.dissent-safe {
    color: var(--green);
    background: var(--green-dim);
    border: 1px solid var(--green-border);
}

/* ── STRESS TEST TABLE ── */
.stress-row-hit {
    background: rgba(0,230,118,0.06) !important;
    border-left: 2px solid var(--green) !important;
}
.stress-row-miss {
    background: rgba(255,45,85,0.04) !important;
}

/* ── ANALYTICS PANEL ── */
.analytics-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
    position: relative;
    overflow: hidden;
}
.analytics-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--blue), transparent);
}
.analytics-card-title {
    font-family: var(--mono);
    font-size: 0.58rem;
    color: var(--blue);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 0.8rem;
    font-weight: 600;
}

/* ── THRESHOLD MATRIX ── */
.th-matrix {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 0.7rem;
}
.th-matrix th {
    background: var(--bg-card-hi);
    color: var(--amber);
    font-size: 0.58rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 0.6rem 0.8rem;
    border: 1px solid var(--border-hi);
    text-align: center;
}
.th-matrix td {
    padding: 0.5rem 0.8rem;
    border: 1px solid var(--border);
    color: var(--text);
    text-align: center;
}
.th-matrix tr:hover td {
    background: rgba(0,180,255,0.04);
}
.th-matrix .best-cell {
    color: var(--green);
    font-weight: 600;
    text-shadow: 0 0 8px rgba(0,230,118,0.3);
}

/* ── WEIGHTED VOTING BAR ── */
.weight-bar-wrap {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.2rem 0;
}
.weight-bar-label {
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    letter-spacing: 0.1em;
    min-width: 40px;
    text-align: right;
}
.weight-bar-track {
    flex: 1;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
}
.weight-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--blue), var(--amber));
    border-radius: 2px;
    transition: width 0.4s cubic-bezier(0.16,1,0.3,1);
}

/* ── HIDE STREAMLIT CHROME ── */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }
</style>
""", unsafe_allow_html=True)

# ======================================================
# SESSION STATE
# ======================================================
if "batch_results" not in st.session_state:
    st.session_state.batch_results = None
if "batch_evidence" not in st.session_state:
    st.session_state.batch_evidence = None
if "batch_run" not in st.session_state:
    st.session_state.batch_run = False

# ======================================================
# LOAD MODELS
# ======================================================
@st.cache_resource
def load_models():
    return (
        joblib.load("models_new/tfidf.pkl"),
        joblib.load("models_new/logistic.pkl"),
        joblib.load("models_new/rf.pkl"),
        joblib.load("models_new/xgb.pkl"),
        joblib.load("models_new/thresholds.pkl")
    )

tfidf, logistic, rf, xgb, thresholds = load_models()
tldextract.extract("google.com")

DEFAULT_THRESHOLDS = {
    "Logistic Regression": thresholds["log_th"],
    "Random Forest":       thresholds["rf_th"],
    "XGBoost":             thresholds["xgb_th"],
    "Ensemble (Majority Vote)": 0.5,
}

# Ensemble weights — XGBoost strongest, RF second, LR third
ENSEMBLE_WEIGHTS = {"lr": 0.25, "rf": 0.35, "xgb": 0.40}

# ======================================================
# FEATURE CONFIG
# ======================================================
BRANDS      = ["google","facebook","amazon","microsoft","apple",
               "paypal","netflix","instagram","linkedin","twitter"]
RISKY_TLDS  = {"tk","ml","ga","cf","gq"}
KEYWORDS    = ["login","verify","secure","account",
               "update","bank","confirm","signin"]
BRAND_ALERT_TH = 0.8

# ======================================================
# FEATURE EXTRACTION
# ======================================================
def brand_similarity(domain):
    best = 0
    for b in BRANDS:
        best = max(best, SequenceMatcher(None, domain, b).ratio())
    return best

def keyword_score(url):
    url = url.lower()
    return sum(k in url for k in KEYWORDS)

def is_ip(domain):
    return int(bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain)))

def extract_features(url):
    parsed    = urlparse(url)
    ext       = tldextract.extract(url)
    subdomain = ext.subdomain
    feats = {
        "url_length":       len(url),
        "num_dots":         url.count("."),
        "num_hyphens":      url.count("-"),
        "num_digits":       sum(c.isdigit() for c in url),
        "has_https_token":  int("https" in parsed.path.lower()),
        "is_ip":            is_ip(parsed.netloc),
        "keyword_score":    keyword_score(url),
        "brand_similarity": brand_similarity(ext.domain),
        "risky_tld":        int(ext.suffix in RISKY_TLDS),
        "subdomain_count":  0 if subdomain == "" else subdomain.count(".") + 1,
    }
    return pd.DataFrame([feats]), ext

# ======================================================
# INFERENCE
# ======================================================
def get_probs(url):
    X      = tfidf.transform([url])
    log_p  = logistic.predict_proba(X)[0][1]
    struct, ext = extract_features(url)
    rf_p   = rf.predict_proba(struct)[0][1]
    xgb_p  = xgb.predict_proba(struct)[0][1]
    return log_p, rf_p, xgb_p, struct.iloc[0], ext

@st.cache_data(show_spinner=False)
def cached_probs(url):
    return get_probs(url)

# ======================================================
# ENSEMBLE PREDICTION
# ======================================================
def ensemble_predict(lp, rfp, xp, voting_threshold=0.5, min_votes=2, mode="hard"):
    """Ensemble prediction across all three classifiers.
    Modes:
      hard     — majority vote (count models above voting_threshold)
      soft     — average probabilities, compare to voting_threshold
      weighted — weighted average using ENSEMBLE_WEIGHTS
    Returns: (confidence, is_phishing, votes)
    """
    lr_vote = int(lp > voting_threshold)
    rf_vote = int(rfp > voting_threshold)
    xgb_vote = int(xp > voting_threshold)
    votes = lr_vote + rf_vote + xgb_vote

    if mode == "soft":
        confidence = (lp + rfp + xp) / 3.0
        is_phishing = int(confidence >= voting_threshold)
    elif mode == "weighted":
        w = ENSEMBLE_WEIGHTS
        confidence = w["lr"] * lp + w["rf"] * rfp + w["xgb"] * xp
        is_phishing = int(confidence >= voting_threshold)
    else:  # hard
        confidence = (lp + rfp + xp) / 3.0
        is_phishing = int(votes >= min_votes)

    return confidence, is_phishing, votes

def get_confidence_tier(votes):
    """Return (label, css_class) based on vote count."""
    if votes == 3:
        return "CRITICAL THREAT", "tier-critical"
    elif votes == 2:
        return "PROBABLE THREAT", "tier-probable"
    elif votes == 1:
        return "LOW RISK", "tier-low"
    else:
        return "CLEAR", "tier-clear"

def active_score(lp, rfp, xp, model_mode, threshold, min_votes=2, voting_mode="hard"):
    if model_mode == "Ensemble (Majority Vote)":
        return ensemble_predict(lp, rfp, xp, voting_threshold=threshold,
                                min_votes=min_votes, mode=voting_mode)
    prob = {"Logistic Regression": lp, "Random Forest": rfp, "XGBoost": xp}[model_mode]
    return prob, int(prob >= threshold), None  # votes=None for single models

def verdict_label(pred):
    return "⚠ Phishing" if pred else "✅ Legitimate"

# ======================================================
# SIDEBAR
# ======================================================
with st.sidebar:
    st.markdown(f"""
    <div class="sb-head">
        <div class="sb-logo">PHISH<span>SCOPE</span></div>
        <div class="sb-sub">
            <span style="display:inline-block;width:5px;height:5px;border-radius:50%;
                background:#00e676;box-shadow:0 0 6px #00e676;margin-right:0.4rem;
                vertical-align:middle;animation:dot-pulse 2.5s ease-in-out infinite;"></span>
            SOC Detection Platform
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.58rem;color:#3a4a5c;'
                'letter-spacing:0.18em;text-transform:uppercase;margin:0.8rem 0 0.3rem 0.1rem;">Detection Model</p>',
                unsafe_allow_html=True)
    model_mode = st.selectbox("Detection Model",
                               ["Logistic Regression", "Random Forest", "XGBoost",
                                "Ensemble (Majority Vote)"],
                               label_visibility="collapsed")

    is_ensemble = model_mode == "Ensemble (Majority Vote)"

    st.markdown("<hr class='sb-divider'>", unsafe_allow_html=True)

    # ── Ensemble-specific controls ──
    if is_ensemble:
        st.markdown('<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.58rem;color:#3a4a5c;'
                    'letter-spacing:0.18em;text-transform:uppercase;margin-bottom:0.3rem;">'
                    'Voting Mode</p>', unsafe_allow_html=True)
        voting_mode = st.selectbox("Voting Mode",
                                    ["Hard (Majority Vote)", "Soft (Average Prob)", "Weighted (XGB-Heavy)"],
                                    label_visibility="collapsed")
        voting_mode_key = {"Hard (Majority Vote)": "hard",
                           "Soft (Average Prob)": "soft",
                           "Weighted (XGB-Heavy)": "weighted"}[voting_mode]

        st.markdown('<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.58rem;color:#3a4a5c;'
                    'letter-spacing:0.18em;text-transform:uppercase;margin:0.5rem 0 0.3rem;">'
                    'Per-Model Voting Threshold</p>', unsafe_allow_html=True)
        threshold = st.slider("Voting Threshold", 0.0, 1.0, 0.5, 0.01,
                              label_visibility="collapsed")

        if voting_mode_key == "hard":
            st.markdown('<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.58rem;color:#3a4a5c;'
                        'letter-spacing:0.18em;text-transform:uppercase;margin:0.5rem 0 0.3rem;">'
                        'Min Votes for Phishing</p>', unsafe_allow_html=True)
            min_votes = st.selectbox("Min Votes", [1, 2, 3], index=1,
                                     label_visibility="collapsed")
        else:
            min_votes = 2  # not used in soft/weighted but keep default

        # Show weight distribution for weighted mode
        if voting_mode_key == "weighted":
            st.markdown(f"""
            <div style="margin-top:0.5rem;">
                <div class="weight-bar-wrap">
                    <span class="weight-bar-label">LR</span>
                    <div class="weight-bar-track"><div class="weight-bar-fill" style="width:25%;"></div></div>
                    <span style="font-family:var(--mono);font-size:0.6rem;color:var(--text-hi);">{ENSEMBLE_WEIGHTS['lr']}</span>
                </div>
                <div class="weight-bar-wrap">
                    <span class="weight-bar-label">RF</span>
                    <div class="weight-bar-track"><div class="weight-bar-fill" style="width:35%;"></div></div>
                    <span style="font-family:var(--mono);font-size:0.6rem;color:var(--text-hi);">{ENSEMBLE_WEIGHTS['rf']}</span>
                </div>
                <div class="weight-bar-wrap">
                    <span class="weight-bar-label">XGB</span>
                    <div class="weight-bar-track"><div class="weight-bar-fill" style="width:40%;"></div></div>
                    <span style="font-family:var(--mono);font-size:0.6rem;color:var(--text-hi);">{ENSEMBLE_WEIGHTS['xgb']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        voting_mode_key = "hard"
        min_votes = 2
        th_label = model_mode.split()[0]
        st.markdown(f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.58rem;color:#3a4a5c;'
                    f'letter-spacing:0.18em;text-transform:uppercase;margin-bottom:0.3rem;">'
                    f'Decision Threshold — {th_label}</p>', unsafe_allow_html=True)
        threshold = st.slider("Threshold", 0.0, 1.0,
                              float(DEFAULT_THRESHOLDS[model_mode]), 0.01,
                              label_visibility="collapsed")

    st.markdown("<hr class='sb-divider'>", unsafe_allow_html=True)

    model_display = "Ensemble" if is_ensemble else model_mode.split()[0]
    engine_display = "LR+RF+XGB Vote" if is_ensemble else "TF-IDF + Lex"
    voting_display = voting_mode_key.capitalize() if is_ensemble else "—"

    config_html = f"""<div class="sb-config"><div style="font-family:'IBM Plex Mono',monospace;font-size:0.55rem;color:#3a4a5c;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:0.5rem;">Active Config</div><div class="sb-cfg-row"><span class="sb-cfg-key">Model</span><span class="sb-cfg-val">{model_display}</span></div><div class="sb-cfg-row"><span class="sb-cfg-key">Threshold</span><span class="sb-cfg-val">{threshold:.3f}</span></div><div class="sb-cfg-row"><span class="sb-cfg-key">Engine</span><span class="sb-cfg-val">{engine_display}</span></div>"""
    if is_ensemble:
        config_html += f"""<div class="sb-cfg-row"><span class="sb-cfg-key">Vote Mode</span><span class="sb-cfg-val">{voting_display}</span></div><div class="sb-cfg-row"><span class="sb-cfg-key">Min Votes</span><span class="sb-cfg-val">{min_votes}/3</span></div>"""
    config_html += "</div>"
    st.markdown(config_html, unsafe_allow_html=True)

    st.markdown("<hr class='sb-divider'>", unsafe_allow_html=True)

    st.markdown("""
    <div class="sb-info">
        <div><span class="sb-info-dot"></span>Corpus · 186,230 URLs</div>
        <div><span class="sb-info-dot"></span>Features · TF-IDF + Lexical</div>
        <div><span class="sb-info-dot"></span>Ensemble · LR + RF + XGB</div>
        <div><span class="sb-info-dot"></span>PSL Cache · Warm</div>
    </div>
    """, unsafe_allow_html=True)

# ======================================================
# HEADER
# ======================================================
st.markdown("""
<div class="pg-header">
    <div>
        <div class="pg-wordmark">PHISH<em>SCOPE</em></div>
        <div class="pg-meta">
            <span class="pg-tagline">Security Operations Center</span>
            <span class="pg-sep">·</span>
            <span class="pg-tagline">URL Threat Intelligence</span>
        </div>
    </div>
    <div class="pg-right">
        <div class="pg-status">
            <div class="pg-dot"></div>
            All Systems Nominal
        </div>
        <div class="pg-corpus">186,230 URL Corpus · v2.1.4</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ======================================================
# TABS
# ======================================================
single_tab, batch_tab, ensemble_tab = st.tabs(["▸  Single URL Investigation", "▸  Batch Scan", "▸  Ensemble Analytics"])

# =====================================================
# SINGLE TAB
# =====================================================
with single_tab:
    with st.form("single_form"):
        url = st.text_input("Target URL", placeholder="https://example.com/login?verify=account")
        analyse = st.form_submit_button("▶  Initiate Analysis")

    if analyse:
        if not url.strip():
            st.warning("Enter a URL to analyse.")
        else:
            with st.spinner(""):
                lp, rfp, xp, struct, ext = get_probs(url)
            score, pred, votes = active_score(lp, rfp, xp, model_mode, threshold,
                                               min_votes, voting_mode_key)

            # ── Ensemble extras ──
            is_ens = model_mode == "Ensemble (Majority Vote)"
            tier_label, tier_cls = "", ""
            vote_dots_html = ""
            if is_ens and votes is not None:
                tier_label, tier_cls = get_confidence_tier(votes)
                dots = []
                for v in [lp > threshold, rfp > threshold, xp > threshold]:
                    dots.append(f'<span class="em-dot {"active-phish" if v else "active-safe"}"></span>')
                vote_dots_html = f"""
                <div class="ensemble-meter">
                    {''.join(dots)}
                    <span class="em-label">{votes}/3 models vote phishing</span>
                    <span class="conf-tier {tier_cls}">{tier_label}</span>
                </div>"""

            # ── Verdict Banner ───────────────────────
            bar_pct = f"{score*100:.1f}%"
            model_label = model_mode if not is_ens else f"Ensemble ({voting_mode_key.capitalize()})"
            if pred:
                st.markdown(f"""
                <div class="verdict-wrap verdict-phish">
                    <div class="v-eyebrow phish">Threat Classification</div>
                    <div class="v-label phish">⚠  PHISHING DETECTED</div>{vote_dots_html}
                    <div class="v-meta">
                        <div class="v-pill">
                            <span class="v-pill-label">Confidence Score</span>
                            <span class="v-pill-val">{score:.4f}</span>
                        </div>
                        <div class="v-pill">
                            <span class="v-pill-label">Active Model</span>
                            <span class="v-pill-val">{model_label}</span>
                        </div>
                        <div class="v-pill">
                            <span class="v-pill-label">Decision Threshold</span>
                            <span class="v-pill-val">{threshold:.3f}</span>
                        </div>
                    </div>
                    <div class="threat-bar-wrap">
                        <div style="font-family:'IBM Plex Mono',monospace;font-size:0.52rem;color:#5a6e84;
                                    letter-spacing:0.14em;text-transform:uppercase;">Threat Level</div>
                        <div class="threat-bar-track">
                            <div class="threat-bar-fill-phish" style="width:{bar_pct};"></div>
                        </div>
                    </div>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="verdict-wrap verdict-safe">
                    <div class="v-eyebrow safe">Threat Classification</div>
                    <div class="v-label safe">✓  LEGITIMATE</div>{vote_dots_html}
                    <div class="v-meta">
                        <div class="v-pill">
                            <span class="v-pill-label">Confidence Score</span>
                            <span class="v-pill-val">{score:.4f}</span>
                        </div>
                        <div class="v-pill">
                            <span class="v-pill-label">Active Model</span>
                            <span class="v-pill-val">{model_label}</span>
                        </div>
                        <div class="v-pill">
                            <span class="v-pill-label">Decision Threshold</span>
                            <span class="v-pill-val">{threshold:.3f}</span>
                        </div>
                    </div>
                    <div class="threat-bar-wrap">
                        <div style="font-family:'IBM Plex Mono',monospace;font-size:0.52rem;color:#5a6e84;
                                    letter-spacing:0.14em;text-transform:uppercase;">Threat Level</div>
                        <div class="threat-bar-track">
                            <div class="threat-bar-fill-safe" style="width:{bar_pct};"></div>
                        </div>
                    </div>
                </div>""", unsafe_allow_html=True)

            # ── Disagreement Alert ────────────────────
            if is_ens and votes is not None and 0 < votes < 3:
                model_votes = [("Logistic Regression", lp), ("Random Forest", rfp), ("XGBoost", xp)]
                dissenters = []
                for mname, mprob in model_votes:
                    voted_phish = mprob > threshold
                    tag_cls = "dissent-phish" if voted_phish else "dissent-safe"
                    tag_lbl = "PHISH" if voted_phish else "SAFE"
                    dissenters.append(f'<span class="da-model-tag {tag_cls}">{mname}: {tag_lbl} ({mprob:.3f})</span>')
                st.markdown(f"""
                <div class="disagree-alert">
                    <div class="da-title">⚡ Model Disagreement Detected</div>
                    <div class="da-body">
                        Models split {votes}/3 on this URL. Individual verdicts:<br>
                        {'&nbsp;&nbsp;'.join(dissenters)}
                    </div>
                </div>""", unsafe_allow_html=True)

            col_a, col_b = st.columns([1, 1], gap="large")

            # ── Model Breakdown ──────────────────────
            with col_a:
                st.markdown('<div class="sect">Model Probability Breakdown</div>',
                            unsafe_allow_html=True)
                models_data = [
                    ("Logistic Regression", lp),
                    ("Random Forest",       rfp),
                    ("XGBoost",             xp),
                ]
                for name, prob in models_data:
                    bar_color = "#ff2d55" if prob >= threshold else "#00e676"
                    active_mark = '<span class="model-active-mark">active</span>' if name == model_mode else ""
                    # Vote badge for ensemble mode
                    vote_badge = ""
                    if is_ens:
                        if prob > threshold:
                            vote_badge = '<span class="vote-badge vote-badge-phish">vote: phish</span>'
                        else:
                            vote_badge = '<span class="vote-badge vote-badge-safe">vote: safe</span>'
                    st.markdown(f"""
                    <div class="model-row">
                        <span class="model-name">{name}{active_mark}{vote_badge}</span>
                        <div class="model-track">
                            <div class="model-fill"
                                 style="width:{prob*100:.1f}%;
                                        background:linear-gradient(90deg,{bar_color}88,{bar_color});
                                        box-shadow:0 0 6px {bar_color}66;"></div>
                        </div>
                        <span class="model-val">{prob:.4f}</span>
                    </div>
                    """, unsafe_allow_html=True)

            # ── Feature Signals ──────────────────────
            with col_b:
                st.markdown('<div class="sect">Feature Signal Analysis</div>',
                            unsafe_allow_html=True)
                risky_tld_val = "YES" if struct["risky_tld"] else "NO"
                risky_cls     = "warn" if struct["risky_tld"] else "ok"
                kw_cls        = "warn" if struct["keyword_score"] > 0 else "ok"
                brand_cls     = "warn" if struct["brand_similarity"] > BRAND_ALERT_TH else "ok"
                ip_cls        = "warn" if struct["is_ip"] else "ok"
                url_cls       = "note" if struct["url_length"] > 75 else ""

                st.markdown(f"""
                <div class="feat-grid">
                    <div class="feat-cell">
                        <div class="feat-key">Domain</div>
                        <div class="feat-val">{ext.domain or "—"}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">TLD</div>
                        <div class="feat-val {risky_cls}">.{ext.suffix or "—"}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">Risky TLD</div>
                        <div class="feat-val {risky_cls}">{risky_tld_val}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">Subdomains</div>
                        <div class="feat-val">{int(struct["subdomain_count"])}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">Keyword Score</div>
                        <div class="feat-val {kw_cls}">{int(struct["keyword_score"])}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">Brand Similarity</div>
                        <div class="feat-val {brand_cls}">{struct["brand_similarity"]:.2f}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">URL Length</div>
                        <div class="feat-val {url_cls}">{int(struct["url_length"])}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">Digit Count</div>
                        <div class="feat-val">{int(struct["num_digits"])}</div>
                    </div>
                    <div class="feat-cell">
                        <div class="feat-key">IP-Based</div>
                        <div class="feat-val {ip_cls}">{'YES' if struct['is_ip'] else 'NO'}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

# =====================================================
# BATCH TAB
# =====================================================
with batch_tab:
    col_up, col_btn = st.columns([3, 1], gap="medium")
    with col_up:
        uploaded = st.file_uploader(
            "Upload CSV · must contain a column named 'url'",
            type=["csv"]
        )
    with col_btn:
        st.markdown("<br><br>", unsafe_allow_html=True)
        start = st.button("▶  Start Batch Scan")

    if uploaded and start:
        st.session_state.batch_run = True

    if uploaded and st.session_state.batch_run:
        df = pd.read_csv(uploaded)
        if "url" not in df.columns:
            st.error("CSV must contain a column named 'url'.")
        else:
            df    = df.dropna(subset=["url"]).drop_duplicates(subset=["url"])
            results  = []
            evidence = {"keyword": 0, "risky_tld": 0, "brand": 0, "ip": 0}
            progress = st.progress(0)
            status   = st.empty()
            total    = len(df)
            is_ens_batch = model_mode == "Ensemble (Majority Vote)"

            for i, u in enumerate(df["url"]):
                status.markdown(
                    f'<div class="scan-status">'
                    f'<div class="scan-spinner"></div>'
                    f'Scanning {i+1:,} / {total:,} URLs&nbsp;&nbsp;·&nbsp;&nbsp;'
                    f'{((i+1)/total*100):.0f}% complete'
                    f'</div>',
                    unsafe_allow_html=True
                )
                lp, rfp, xp, struct, _ = cached_probs(str(u))
                score, pred, votes = active_score(lp, rfp, xp, model_mode, threshold,
                                                   min_votes, voting_mode_key)

                if struct["keyword_score"] > 0:              evidence["keyword"]   += 1
                if struct["risky_tld"]:                      evidence["risky_tld"] += 1
                if struct["brand_similarity"] > BRAND_ALERT_TH: evidence["brand"] += 1
                if struct["is_ip"]:                          evidence["ip"]        += 1

                row = {
                    "url":              u,
                    "logistic_prob":    round(lp, 4),
                    "rf_prob":          round(rfp, 4),
                    "xgb_prob":         round(xp, 4),
                    "active_model":     model_mode,
                    "active_threshold": threshold,
                    "active_score":     round(score, 4),
                    "prediction":       pred,
                    "verdict":          verdict_label(pred),
                }
                if is_ens_batch and votes is not None:
                    row["ensemble_votes"] = votes
                    row["ensemble_confidence"] = round((lp + rfp + xp) / 3.0, 4)
                results.append(row)
                progress.progress((i + 1) / total)

            st.session_state.batch_results  = pd.DataFrame(results)
            st.session_state.batch_evidence = evidence
            st.session_state.batch_run      = False
            status.empty()

    if isinstance(st.session_state.batch_results, pd.DataFrame):
        res      = st.session_state.batch_results
        evidence = st.session_state.batch_evidence
        phishing   = int(res["prediction"].sum())
        legit      = len(res) - phishing
        threat_pct = round(phishing / len(res) * 100, 1) if len(res) > 0 else 0

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Summary Metrics ──────────────────────────
        is_ens_res = "ensemble_votes" in res.columns
        if is_ens_res:
            unanimous_ph = int((res["ensemble_votes"] == 3).sum())
            split_dec    = int((res["ensemble_votes"] == 2).sum())
            unanimous_lg = int((res["ensemble_votes"] == 0).sum())
            c1, c2, c3, c4, c5, c6 = st.columns(6)
            c1.metric("Total Scanned",       f"{len(res):,}")
            c2.metric("Phishing",            f"{phishing:,}")
            c3.metric("Legitimate",          f"{legit:,}")
            c4.metric("Unanimous Phish (3/3)", f"{unanimous_ph:,}")
            c5.metric("Split Decision (2/3)",  f"{split_dec:,}")
            c6.metric("Unanimous Safe (0/3)",  f"{unanimous_lg:,}")
        else:
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Scanned",  f"{len(res):,}")
            c2.metric("Phishing",       f"{phishing:,}")
            c3.metric("Legitimate",     f"{legit:,}")
            c4.metric("Threat Rate",    f"{threat_pct}%")
            c5.metric("Active Model",   model_mode.split()[0])

        st.markdown("<br>", unsafe_allow_html=True)

        col_ev, col_res = st.columns([1, 2], gap="large")

        # ── Evidence Summary ─────────────────────────
        with col_ev:
            st.markdown('<div class="sect">Evidence Summary</div>', unsafe_allow_html=True)
            ev_items = [
                ("Keyword Matches",     evidence["keyword"],    "Suspicious auth/security keywords detected"),
                ("Risky TLDs",          evidence["risky_tld"],  f"Free TLD abuse: {', '.join(RISKY_TLDS)}"),
                ("Brand Impersonation", evidence["brand"],      f"Similarity > {BRAND_ALERT_TH} to known brands"),
                ("IP-Based URLs",       evidence["ip"],         "Raw IPv4 used instead of domain"),
            ]
            for label, count, desc in ev_items:
                chip_class = "" if count > 0 else " zero"
                st.markdown(f"""
                <div class="evidence-row">
                    <span class="evidence-chip{chip_class}">{count}</span>
                    <div>
                        <div class="ev-label">{label}</div>
                        <div class="ev-desc">{desc}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        # ── Results Table ────────────────────────────
        with col_res:
            st.markdown('<div class="sect">Scan Results</div>', unsafe_allow_html=True)

            filt_col, _ = st.columns([1.5, 2])
            with filt_col:
                filt = st.selectbox("Filter", ["All", "Phishing Only", "Legitimate Only"],
                                    label_visibility="collapsed")
            show = res.copy()
            if filt == "Phishing Only":
                show = show[show.prediction == 1]
            elif filt == "Legitimate Only":
                show = show[show.prediction == 0]

            st.dataframe(show, use_container_width=True, height=300)

            st.markdown("<br>", unsafe_allow_html=True)
            st.download_button(
                "↓  Download Investigation Report (CSV)",
                res.to_csv(index=False).encode("utf-8"),
                "phishscope_soc_report.csv",
                "text/csv"
            )

# =====================================================
# ENSEMBLE ANALYTICS TAB
# =====================================================
with ensemble_tab:

    # ── Stress Test URLs ──
    STRESS_URLS = [
        # Phishing variants
        "http://paypal-secure-login.tk/verify/account",
        "http://192.168.1.1/signin/update-bank",
        "http://g00gle-login.ml/secure/confirm",
        "http://amaz0n.account-verify.ga/login",
        "http://microsoft-update.cf/signin/secure",
        "http://netflix-renew.gq/account/verify",
        "http://apple.id-confirm.tk/login-secure",
        "http://faceb00k-verify.ml/confirm/account",
        "http://linkedin-secure.ga/update/signin",
        "http://paypal.com.suspicious-domain.tk/login",
        # Legitimate URLs
        "https://www.google.com",
        "https://www.facebook.com",
        "https://www.amazon.com/gp/homepage",
        "https://www.microsoft.com/en-us",
        "https://www.apple.com",
        "https://www.paypal.com/myaccount",
        "https://www.netflix.com/browse",
        "https://www.instagram.com",
        "https://www.linkedin.com/feed",
        "https://github.com/explore",
    ]
    STRESS_LABELS = [1]*10 + [0]*10  # 1=phishing, 0=legit

    st.markdown('<div class="sect">Ensemble Stress Test — Adversarial URL Battery</div>',
                unsafe_allow_html=True)

    if st.button("▶  Run Stress Test", key="stress_btn"):
        stress_results = []
        stress_progress = st.progress(0)
        for idx, surl in enumerate(STRESS_URLS):
            lp, rfp, xp, _, _ = get_probs(surl)
            # Individual model predictions
            lr_pred = int(lp > 0.5)
            rf_pred = int(rfp > 0.5)
            xgb_pred = int(xp > 0.5)
            # Ensemble
            ens_conf, ens_pred, ens_votes = ensemble_predict(lp, rfp, xp, 0.5, 2, "hard")
            true_label = STRESS_LABELS[idx]
            # Did ensemble correct an individual model error?
            lr_correct  = (lr_pred == true_label)
            rf_correct  = (rf_pred == true_label)
            xgb_correct = (xgb_pred == true_label)
            ens_correct = (ens_pred == true_label)
            corrected = ens_correct and not (lr_correct and rf_correct and xgb_correct)

            stress_results.append({
                "URL": surl[:60] + ("…" if len(surl) > 60 else ""),
                "True": "PHISH" if true_label else "LEGIT",
                "LR": round(lp, 3),
                "RF": round(rfp, 3),
                "XGB": round(xp, 3),
                "Votes": ens_votes,
                "Ensemble": "PHISH" if ens_pred else "LEGIT",
                "Confidence": round(ens_conf, 3),
                "Corrected": "✓" if corrected else "",
            })
            stress_progress.progress((idx + 1) / len(STRESS_URLS))

        stress_df = pd.DataFrame(stress_results)
        st.session_state["stress_df"] = stress_df

    if "stress_df" in st.session_state:
        stress_df = st.session_state["stress_df"]
        st.dataframe(stress_df, use_container_width=True, height=400)

        # Accuracy metrics
        true_labels = np.array(STRESS_LABELS)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sect">Model vs Ensemble Accuracy</div>', unsafe_allow_html=True)

        # Recompute from raw data for accuracy
        lr_preds, rf_preds, xgb_preds, ens_preds = [], [], [], []
        for surl in STRESS_URLS:
            lp, rfp, xp, _, _ = cached_probs(surl)
            lr_preds.append(int(lp > 0.5))
            rf_preds.append(int(rfp > 0.5))
            xgb_preds.append(int(xp > 0.5))
            _, ep, _ = ensemble_predict(lp, rfp, xp, 0.5, 2, "hard")
            ens_preds.append(ep)

        lr_acc  = np.mean(np.array(lr_preds) == true_labels) * 100
        rf_acc  = np.mean(np.array(rf_preds) == true_labels) * 100
        xgb_acc = np.mean(np.array(xgb_preds) == true_labels) * 100
        ens_acc = np.mean(np.array(ens_preds) == true_labels) * 100

        # Metrics row
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Logistic Regression", f"{lr_acc:.1f}%")
        mc2.metric("Random Forest",       f"{rf_acc:.1f}%")
        mc3.metric("XGBoost",             f"{xgb_acc:.1f}%")
        mc4.metric("Ensemble",            f"{ens_acc:.1f}%")

        # Plotly comparison chart
        try:
            import plotly.graph_objects as go

            fig = go.Figure()
            models_names = ["Logistic\nRegression", "Random\nForest", "XGBoost", "Ensemble"]
            accs = [lr_acc, rf_acc, xgb_acc, ens_acc]
            colors = ["#00b4ff", "#f0a500", "#ff9100", "#00e676"]

            fig.add_trace(go.Bar(
                x=models_names, y=accs,
                marker_color=colors,
                text=[f"{a:.1f}%" for a in accs],
                textposition="outside",
                textfont=dict(family="IBM Plex Mono", size=13, color="#c8daea"),
            ))
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#080b0f",
                plot_bgcolor="#0c1018",
                font=dict(family="IBM Plex Mono", color="#8fa4bc"),
                yaxis=dict(title="Accuracy (%)", range=[0, 110],
                           gridcolor="#161e28", zerolinecolor="#161e28"),
                xaxis=dict(gridcolor="#161e28"),
                margin=dict(l=40, r=20, t=30, b=40),
                height=350,
                bargap=0.35,
            )
            st.plotly_chart(fig, use_container_width=True)
        except ImportError:
            st.info("Install plotly for accuracy chart: `pip install plotly`")

        # ── Corrections highlight ──
        corrections = stress_df[stress_df["Corrected"] == "✓"]
        if len(corrections) > 0:
            st.markdown('<div class="sect">Ensemble Corrections — Caught by Ensemble, Missed by Individual Models</div>',
                        unsafe_allow_html=True)
            st.dataframe(corrections, use_container_width=True)

    # ── Threshold Optimization ──
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="sect">Threshold Optimization Matrix</div>', unsafe_allow_html=True)

    if st.button("▶  Run Threshold Sweep", key="sweep_btn"):
        sweep_thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
        sweep_min_votes  = [1, 2, 3]
        true_labels = np.array(STRESS_LABELS)

        # Gather all probs once
        all_probs = []
        for surl in STRESS_URLS:
            lp, rfp, xp, _, _ = cached_probs(surl)
            all_probs.append((lp, rfp, xp))

        rows_html = ""
        best_acc = 0
        for mv in sweep_min_votes:
            for th in sweep_thresholds:
                preds = []
                for lp, rfp, xp in all_probs:
                    _, ep, _ = ensemble_predict(lp, rfp, xp, th, mv, "hard")
                    preds.append(ep)
                preds = np.array(preds)
                acc = np.mean(preds == true_labels) * 100
                tp = int(np.sum((preds == 1) & (true_labels == 1)))
                fp = int(np.sum((preds == 1) & (true_labels == 0)))
                fn = int(np.sum((preds == 0) & (true_labels == 1)))
                tn = int(np.sum((preds == 0) & (true_labels == 0)))
                prec = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
                rec  = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
                f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
                cell_cls = ' class="best-cell"' if acc > best_acc else ''
                if acc > best_acc:
                    best_acc = acc
                rows_html += f"""<tr>
                    <td>{mv}</td><td>{th}</td>
                    <td{cell_cls}>{acc:.1f}%</td>
                    <td>{prec:.1f}%</td><td>{rec:.1f}%</td><td>{f1:.1f}%</td>
                    <td>{fp}</td><td>{fn}</td>
                </tr>"""

        st.markdown(f"""
        <div class="analytics-card">
            <div class="analytics-card-title">Hard Vote — Threshold × Min Votes Sweep</div>
            <table class="th-matrix">
                <thead>
                    <tr><th>Min Votes</th><th>Threshold</th><th>Accuracy</th>
                        <th>Precision</th><th>Recall</th><th>F1</th>
                        <th>FP</th><th>FN</th></tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
        """, unsafe_allow_html=True)