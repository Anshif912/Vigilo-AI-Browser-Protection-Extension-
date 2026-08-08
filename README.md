# Vigilo IntelligenceOS

> **Autonomous AI Browser Security & Threat Intelligence Engine**
> *Enterprise-grade real-time web protection, automated threat story explanations, and SOC intelligence workflow.*

```text
  ██╗   ██╗██╗██████╗ ██╗██╗      ██████╗ 
  ██║   ██║██║██╔════╝ ██║██║     ██╔═══██╗
  ██║   ██║██║██║  ███╗██║██║     ██║   ██║
  ╚██╗ ██╔╝██║██║   ██║██║██║     ██║   ██║
   ╚████╔╝ ██║╚██████╔╝██║███████╗╚██████╔╝
    ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝ ╚═════╝ 
```

---

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688?style=flat-square&logo=fastapi)
![Manifest v3](https://img.shields.io/badge/Chrome_Extension-Manifest_v3-4285F4?style=flat-square&logo=googlechrome)
![AI Security](https://img.shields.io/badge/AI_Engine-Vigilo_v3.5-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.5.0-orange?style=flat-square)

---

## 📋 Executive Overview

**Vigilo IntelligenceOS** is a high-performance open-source cybersecurity platform designed to protect users against advanced credential phishing, typosquatting, zero-day malware links, and disposable cloud hosting abuse.

### Problem Addressed
Traditional threat detection relies heavily on static domain blacklists, leaving a dangerous time window during which new phishing campaigns operate undetected. Modern attackers leverage automated subdomain generators, free cloud hosting services (`repl.co`, `workers.dev`, `pages.dev`), and brand typosquatting to harvest credentials before blacklists update.

### The Vigilo Solution
Vigilo combines a **21-Rule Threat Fusion Decision Engine** with an **Autonomous Manifest v3 Chrome Extension** and an **AI Threat Story Engine**. It passively intercepts browser navigation, analyzes structural domain heuristics and client-side DOM warnings in real-time, blocks malicious destinations, and presents a non-technical 15-second narrative explaining the threat.

---

## 🏗️ System Architecture

```text
+-------------------------------------------------------------------+
|                        Browser Navigation                         |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|               Chrome Extension (Manifest v3 Interceptor)          |
|  - Passive Tab Listener   - Client DOM Inspector (Rule 21)        |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                  FastAPI Threat Analysis Backend                  |
|                 (REST API endpoint /api/analyze-url)              |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                  21-Rule Threat Fusion Engine                     |
|  - Brand Typosquatting    - Entropy & Obfuscation Analysis        |
|  - Subdomain Abuse        - Browser Security Warning Matching     |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                 Vigilo AI Threat Story Engine                     |
|           (Generates 120-180 word narrative < 0.1ms)              |
+-------------------------------------------------------------------+
                                  |
          +-----------------------+-----------------------+
          |                                               |
          v                                               v
+------------------------------------+   +------------------------------------+
|  Inline Blocked Interstitial Page  |   |   SOC Intelligence OS Dashboard    |
| (Threat Story + Multilingual UI)   |   |   (Campaigns, Timelines, Reports)  |
+------------------------------------+   +------------------------------------+
```

---

## ✨ Key Features

- [x] **Real-Time Autonomous Protection**: Intercepts tab navigation in Chrome and evaluates URL safety in < 150 ms.
- [x] **21-Rule Threat Fusion Engine**: Evaluates domain entropy, brand impersonation, zero-padded subdomains, and dynamic DNS providers.
- [x] **AI Threat Story Engine**: Generates human-friendly, 120-180 word threat stories without technical jargon in < 0.1 ms.
- [x] **Browser Interstitial Warning Detection**: Automatically detects Cloudflare, Google Safe Browsing, SmartScreen, and Firefox warning pages.
- [x] **Multilingual Support**: In-app language switching across 6 languages: English (`en`), Tamil (`ta`), Hindi (`hi`), Kannada (`kn`), Telugu (`te`), and Malayalam (`ml`).
- [x] **Apple VisionOS & MagicBento Ambient UI**: Glassmorphic UI featuring a 6-layer cyber mesh background and card-relative proximity cursor lighting.
- [x] **SOC Intelligence Dashboard**: 3-panel Security Operations Center workspace featuring campaign summaries, threat timelines, and PDF/JSON exports.
- [x] **Privacy-First Architecture**: Zero credential capture, no browsing history stored, and local-first evaluation.

---

## 📷 Interface Previews

> *Note: Placeholders for visual artifacts in documentation.*

### Extension Popup
*Compact extension popup showing active protection status, threat score, and instant language switcher.*

### Blocked Interstitial Page
*Full-screen threat prevention page displaying intercepted target, risk status, Threat Story explanation, and export controls.*

### AI Threat Story Card
*Expandable glassmorphic card explaining target impersonation, attacker goals, detection reasons, and potential impact.*

### SOC Intelligence Dashboard
*3-panel enterprise workspace for threat analysts featuring live campaign tracking and automated report exporting.*

---

## ⚡ Installation & Setup

### Prerequisites
- **Python**: 3.11 or higher
- **Node.js**: 18.0 or higher (npm 9+)
- **Browser**: Google Chrome, Brave, or Chromium-based browser

---

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Start FastAPI Uvicorn Server
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

*The backend server will run at `http://127.0.0.1:8000`.*

---

### 2. Chrome Extension Setup

```bash
# Navigate to extension directory
cd extension

# Install dependencies
npm install

# Build extension dist package
npm run build
```

---

### 3. SOC Dashboard Setup

```bash
# Navigate to dashboard directory
cd dashboard

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```

*The dashboard will run at `http://localhost:5173`.*

---

## 🧩 Loading the Unpacked Chrome Extension

This project is designed for execution as an **Unpacked Extension** in Developer Mode.

### Step-by-Step Instructions:

1. Open Google Chrome.
2. Navigate to `chrome://extensions` in the address bar.
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click **Load unpacked** in the top-left menu.
5. In the file picker, select the `extension/` directory (or `extension/dist/` after building).
6. Verify that **Vigilo - AI Browser Protection** appears in your active extensions list.

### Backend Verification:
Ensure the backend server is running on `http://127.0.0.1:8000`. Navigate to a suspicious test site (e.g. `http://0000guatec.davieelchirinos.repl.co`). Vigilo will automatically intercept the request and display the inline **Blocked Page**.

### Common Troubleshooting:
- **API Connection Error**: Verify that Uvicorn is listening on port `8000`.
- **Extension Content Script Inactive**: Reload the extension card in `chrome://extensions` after building.

---

## 📂 Project Structure

```text
vigilo/
├── backend/                  # FastAPI Threat Intelligence Backend
│   ├── main.py               # Server entry point
│   ├── engine/               # 21-Rule Threat Fusion Engine
│   │   ├── fusion_engine.py  # Master Decision Engine
│   │   └── rules/            # Heuristic detection modules (Rule 01 to 21)
│   ├── models/               # Pydantic schemas
│   ├── routers/              # API REST routes
│   └── services/             # Analysis & Threat Story services
├── dashboard/                # React 19 + TypeScript SOC Workspace
│   ├── src/
│   │   ├── App.tsx           # 3-Panel OS layout
│   │   ├── components/       # Explorer, Inspector, Radar, Glass cards
│   │   └── i18n/             # Multilingual localization dictionaries
├── extension/                # Manifest v3 Chrome Extension
│   ├── manifest.json         # Extension manifest & permissions
│   ├── blocked.html          # Interstitial prevention page
│   └── src/
│       ├── background.ts     # Tab interceptor & background service
│       ├── contentScript.ts  # DOM warning inspector
│       ├── components/       # ThreatStoryCard, MagicInteractionEngine
│       └── pages/            # BlockedPage & WarningPage views
├── tests/                    # Unit & Benchmark Test Suite
├── tools/                    # Phishing dataset audit utilities
├── CHANGELOG.md              # Semantic version history
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # MIT License
├── PROJECT_STRUCTURE.md      # Detailed file tree specification
└── SECURITY.md               # Vulnerability disclosure policy
```

---

## 🛡️ Threat Detection Pipeline

```text
Input URL
   │
   ▼
[ 1. Normalization & Canonicalization ] ──► Strips tracking tokens & normalizes TLD
   │
   ▼
[ 2. Heuristic Rule Execution (21 Rules) ] ──► Brand Typosquatting, Entropy, Free Hosting
   │
   ▼
[ 3. Evidence Aggregation ] ─────────────► Compiles matched heuristics & score breakdown
   │
   ▼
[ 4. Confidence & Risk Scoring ] ────────► Calculates threat score (0-100) & confidence
   │
   ▼
[ 5. AI Threat Story Generation ] ───────► Generates 120-180 word narrative (< 0.1ms)
   │
   ▼
[ 6. Enforcement Decision ] ──────────────► Safe / Low Risk / Suspicious / Critical
   │
   ▼
[ 7. User Action ] ─────────────────────► Inline Blocked Interstitial Page & SOC Log
```

---

## 🔬 Technology Stack

| Component | Technologies Used |
| :--- | :--- |
| **Backend API** | Python 3.11+, FastAPI, Uvicorn, Pydantic, SQLite |
| **Extension** | Manifest v3, TypeScript, React 19, Vite, Rollup |
| **SOC Dashboard** | React 19, TypeScript, Tailwind CSS v4, Framer Motion |
| **Design System** | Apple VisionOS Glassmorphism, Canvas 2D Radar, MagicBento Interaction |
| **Localization** | Built-in zero-dependency i18n engine (EN, TA, HI, KN, TE, ML) |

---

## 🔒 Security & Privacy Commitments

- **No Credential Logging**: Vigilo never captures, transmits, or stores passwords, banking numbers, or form data.
- **Zero Browsing Telemetry**: Browsing histories and user identities are never collected or monetized.
- **Privacy-First Design**: All analyses are conducted locally or via encrypted local endpoints.

---

## 🏎️ Performance Benchmarks

- **Analysis Latency**: `< 150 ms` end-to-end API response time.
- **Story Generation Speed**: `< 0.1 ms` in-memory dynamic narrative compilation.
- **Extension Bundle Size**: `< 3 MB` optimized production package.
- **Animation Frame Rate**: Locked 60 FPS GPU-accelerated canvas loops.

---

## 🛣️ Future Roadmap

- [ ] WebAssembly (Wasm) local rule engine for zero-latency offline detection.
- [ ] YARA rule import support for custom enterprise threat signatures.
- [ ] Integration with MITRE ATT&CK enterprise matrix mapping.
- [ ] Firefox WebExtensions API cross-browser port.

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## ✍️ Authors & Acknowledgments

Developed by the **Vigilo Security Team** as an open-source cybersecurity project.
