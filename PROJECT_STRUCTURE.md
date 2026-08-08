# Vigilo IntelligenceOS — Project Structure

This document provides a detailed overview of the Vigilo open-source repository layout, module boundaries, and architectural design.

```text
vigilo/
├── backend/                  # FastAPI Threat Intelligence & Rule Fusion Engine
│   ├── main.py               # Application entry point & middleware registration
│   ├── database/             # SQLite threat storage & database schemas
│   ├── engine/               # Core Threat Fusion Decision Engine
│   │   ├── fusion_engine.py  # 21-Rule Threat Fusion Engine
│   │   └── rules/            # Individual Heuristic Detection Modules (Rule 01 to 21)
│   ├── models/               # Pydantic request and response models
│   ├── routers/              # RESTful API route definitions (/api/analyze-url)
│   └── services/             # URL analysis, brand resolution & Threat Story Engine
├── dashboard/                # React 19 + TypeScript Enterprise SOC Intelligence Workspace
│   ├── index.html            # Dashboard HTML entry point
│   ├── vite.config.ts        # Vite build configuration
│   └── src/
│       ├── App.tsx           # 3-Panel OS Investigation Workspace layout
│       ├── components/       # UI Components (Explorer, Inspector, Radar, Glass Cards)
│       ├── i18n/             # Multilingual localization provider (EN, TA, HI, KN, TE, ML)
│       └── services/         # API integration services
├── extension/                # Manifest v3 Autonomous Chrome Extension
│   ├── manifest.json         # Extension manifest & permissions
│   ├── vite.config.ts        # Rollup build config for background & content scripts
│   ├── blocked.html          # Interstitial attack prevention page
│   ├── popup.html            # Extension popup HTML entry point
│   └── src/
│       ├── background.ts     # Navigation detection listener & tab interceptor
│       ├── contentScript.ts  # DOM warning interstitial inspector & MutationObserver
│       ├── components/       # ThreatStoryCard, LanguageSelector, MagicInteractionEngine
│       ├── pages/            # BlockedPage & WarningPage React views
│       ├── popup/            # PopupApp popup interface
│       └── services/         # ThreatStoryEngine, Storage & Analysis API services
├── tests/                    # Automated Unit & Rule Benchmark Test Suite
│   ├── test_v3_rule_engine.py
│   ├── test_threat_story_engine.py
│   └── test_v3_4_1_interstitial_detection.py
└── tools/                    # Verification & Analysis Utilities
    ├── analyze_top_100.py    # Phishing benchmark dataset batch analyzer
    └── summarize_fn.py       # False Negative audit tool
```

---

## Core Components

### 1. `backend/`
The FastAPI backend houses the **Threat Intelligence Decision Engine** (`fusion_engine.py`). It executes 21 heuristic rules concurrently, evaluates brand typosquatting, free hosting abuse, entropy anomalies, TLS attributes, and browser warnings to return structured risk assessments.

### 2. `extension/`
A Manifest v3 Chrome Extension that passively intercepts navigation events, inspects client-side DOM warnings (Cloudflare, Google Safe Browsing, SmartScreen), runs local/API threat evaluation, and automatically redirects dangerous URLs to an inline interstitial blocked page.

### 3. `dashboard/`
An enterprise 3-panel Security Operations Center (SOC) investigation workspace for real-time campaign tracking, threat timeline visualization, and PDF/JSON export.
