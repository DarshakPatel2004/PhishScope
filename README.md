<div align="center">

<img src="./phishscope_logo.png" width="250" alt="PhishScope Logo" />

# 🛡️ PhishScope
### The Machine Learning Watchtower for Phishing Intelligence

[![GitHub stars](https://img.shields.io/github/stars/DarshakPatel2004/PhishScope?style=for-the-badge&color=00D4FF)](https://github.com/DarshakPatel2004/PhishScope/stargazers)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=24&duration=3000&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=Analyze+URLs+in+Real-time;97%25%2B+Detection+Accuracy;Hybrid+Lexical+%2B+TF-IDF+Ensemble;Built+for+Modern+SOC+Workflows" alt="PhishScope Typing SVG" />

---

**PhishScope** is a high-performance URL classification engine designed to dismantle phishing campaigns before they reach the user. By combining **Character n-gram TF-IDF vectorization** with **Custom Lexical Feature Engineering**, PhishScope provides 180k+ data-point validated intelligence to your security stack.

[Quick Start](#-quick-start) • [Scientific Performance](#-scientific-performance) • [Architecture](#-architecture) • [Features](#-key-capabilities)

</div>

---

## ⚡ Quick Start

> [!TIP]
> Use the **XGBoost** model for the highest precision in high-stakes environments.

```powershell
# 1. Prepare Environment
python -m venv venv; .\venv\Scripts\activate

# 2. Install Engine
pip install -r requirements.txt

# 3. Launch Watchtower
streamlit run app.py
```

---

## 🔍 Key Capabilities

<div align="center">

| Feature | Description | Icon |
| :--- | :--- | :---: |
| **Deep URL Inspection** | Decodes obfuscated patterns and character-level tricks. | 🧪 |
| **Ensemble Inference** | Cross-verify results between **Logistic**, **RF**, and **XGBoost**. | 🧠 |
| **SOC Dynamic Logic** | Real-time threshold adjustment via the **SOC Control Sidebar**. | ⚙️ |
| **Scalable Batching** | Scan thousands of IOCs using the **CSV Upload Pipeline**. | 📂 |
| **Evidence JSON** | Export structured technical evidence for incident response. | 📜 |

</div>

---

## 📊 Scientific Performance

PhishScope models are trained on a massive dataset of **186,230 URLs**, ensuring extremely low false-positive rates.

<div align="center">

| Model | Accuracy | F1-Score | Usage |
| :--- | :---: | :---: | :--- |
| **XGBoost** | `98.2%` | `0.98` | Most balance, high performance |
| **Random Forest** | `97.8%` | `0.97` | Robust to noise |
| **Logistic Reg.** | `96.5%` | `0.96` | Extremely fast inference |

</div>

> [!NOTE]
> *Accuracy stats based on character n-gram (3-5) TF-IDF vectorization on the PhishScope validation split.*

---

## 🏗️ Architecture

```mermaid
graph TD
    A[User Input / CSV Upload] --> B{Preprocessing Engine}
    
    subgraph "Hybrid Feature Extraction"
    B --> C[Lexical Vectorizer]
    B --> D[TF-IDF Analyzer]
    C --> C1[Brand Similarity]
    C --> C2[Risky TLD Check]
    C --> C3[URL Length/Digit Ratio]
    D --> D1[Character n-grams 3-5]
    end
    
    C1 & C2 & C3 & D1 --> E[ML Ensemble Layer]
    
    subgraph "Ensemble Models"
    E --> F[Random Forest]
    E --> G[XGBoost]
    E --> H[Logistic Regression]
    end
    
    F & G & H --> I{SOC Threshold Filter}
    I --> J[Final Verdict & Confidence]
    J --> K[JSON Data Dump / CSV Report]
    
    style A fill#940b09,stroke:#333,stroke-width:2px
    style J fill:#188008,stroke:#333,stroke-width:4px
    style E fill:#444,color:#fff
```

---

## 🧰 Tech Stack & Tools

- **Core Engine:** Python 3.11
- **Inference Layers:** `XGBoost`, `Scikit-Learn`
- **Frontend Dashboard:** `Streamlit`
- **Data Wrangling:** `Pandas`, `NumPy`, `TLDExtract`
- **Security Logic:** Custom heuristic matching via `difflib` and `re`

---

## 📁 Repository Overview

```ascii
PhishScope
├── app.py                      # Main App Logic
├── dataset.csv                 # 186k Sample Dataset
├── models_new/                 # Serialized Brain Components
│   ├── tfidf.pkl               # Feature Vectoriser
│   ├── xgb.pkl                 # Gradient Boosting Model
│   └── thresholds.pkl          # Optimal SOC Defaults
└── notebooks/                  # Experimental Research
    ├── Dataset_Builder.ipynb   # ETL Pipeline
    └── Detection_Logic.ipynb   # Training Labs
```

---

<div align="center">

**Built for the blue team. Zero cloud reliance. Pure ML.**

*Designed with 💙 by Darshak Patel*

[![Made with FastAPI](https://img.shields.io/badge/Made%20with-Python-3776AB?style=for-the-badge&logo=python)](https://fastapi.tiangolo.com)
[![Powered by React](https://img.shields.io/badge/Powered%20by-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit)](https://react.dev)

</div>
