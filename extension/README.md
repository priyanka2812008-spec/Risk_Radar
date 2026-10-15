# 🛡️ Risk Radar — Browser Extension (Manifest V3)

> **Browser-Native Pre-Execution Risk Intelligence**  
> Inspect and analyze any website you visit in real-time — **Zero copy-paste required**.

---

## 🌟 Overview

The **Risk Radar Browser Extension** brings Risk Radar's multi-layered digital risk assessment directly into Chromium-based browsers (Google Chrome, Microsoft Edge, Brave, Opera, Arc).

Instead of forcing users to copy a URL and switch tabs to an analysis portal:
1. **Automatic Active Tab Capture**: Click the Risk Radar icon while browsing any webpage.
2. **Instant Correlation**: The active tab URL is securely sanitized (stripping tracking tokens like UTMs, click IDs, session parameters) and queried against the Risk Radar backend API.
3. **Multi-Vector Threat Signals**: Evaluates Domain Intelligence (age, registrar, ASN), Threat Intelligence feeds, Content & Keyword heuristics, and Contact & Identity verification.
4. **Actionable Decision Support**: Clear Risk Score (0–100), Classification with confidence rating, explicit "UNKNOWN BUT SUSPICIOUS" indicators (preventing *Unknown = Safe* fallacies), and a cryptographic **Digital Risk Passport**.
5. **Seamless Deep Linking**: One-click "Open Full Risk Report" button jumps straight into the full Risk Radar SOC dashboard for in-depth forensic investigation.

---

## 🚀 Installation Guide (Developer Mode)

### Step 1: Open Extension Management
- **Google Chrome**: Navigate to `chrome://extensions` in your address bar.
- **Microsoft Edge**: Navigate to `edge://extensions` in your address bar.
- **Brave**: Navigate to `brave://extensions`.

### Step 2: Enable Developer Mode
- In the top-right corner of the Extensions page, toggle the **"Developer mode"** switch to **ON**.

### Step 3: Load Unpacked Extension
1. Click the **"Load unpacked"** button in the top-left toolbar.
2. In the folder picker dialog, browse to your Risk Radar workspace and select the `extension` folder:
   ```
   Risk radar/
   └── extension/      <-- SELECT THIS FOLDER
       ├── manifest.json
       ├── background/
       ├── popup/
       └── icons/
   ```
3. Click **Select Folder**.
4. The **"Risk Radar — Website Risk Intelligence"** extension is now installed and active!

### Step 4: Pin Extension (Recommended)
- Click the puzzle-piece icon in your browser toolbar (Extensions menu).
- Locate **Risk Radar** and click the **Pin** icon so it remains visible for one-click access.

---

## 🧪 Live Demonstration Flow

### Prerequisites
Make sure the Risk Radar backend and frontend services are running:
```bash
# Terminal 1: Risk Radar Backend
cd backend
node src/server.js
# Verified at: http://localhost:5000/api/health

# Terminal 2: Risk Radar Frontend
cd frontend
npm run dev
# Verified at: http://localhost:5173
```

### Demo Steps:
1. **Visit Any Website**:
   - Open a new browser tab and navigate to any website (e.g., `https://wikipedia.org`, or test scenarios like newly registered promo domains).
2. **Click the Risk Radar Extension Icon**:
   - The popup opens and immediately shows the current domain in the header strip.
   - You do **NOT** need to copy or paste anything.
3. **Watch Real-Time Stage Processing**:
   - An animated scanning radar sweep displays stage-by-stage pipeline verification (Normalization → Domain Intel → Threat Databases → Heuristic Content → Correlation Engine).
4. **Inspect the Risk Assessment**:
   - **Risk Gauge**: Visual 0–100 dial with risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - **Classification & Confidence**: Industry classification with confidence percentage (e.g., `Informational (90%)`, `Gambling / Sweepstakes (75%)`).
   - **Heuristic Warning Badges**: Displays high-risk alerts and `UNKNOWN BUT SUSPICIOUS` callouts when a domain is new or unverified despite having no prior blacklisting.
   - **Evidence Signals**: Detailed breakdown of Domain Age, Registrar, SSL encryption, and Threat Intel status.
   - **Identity & Contact Audit**: Verification of email, telephone, postal address, and corporate registration to highlight anonymous scam operators.
5. **Explore Forensic Tools**:
   - Click **"Digital Risk Passport"** to view verifiable infrastructure metadata (ASN, Country, Registrar, Token).
   - Click **"Open Full Risk Report"** to open a new tab directly in Risk Radar (`http://localhost:5173/?scan=domain`) with the target domain pre-analyzed in the full analyst console.
   - Click the **History** button (top right clock icon) to review past evaluated domains and re-inspect them instantly.

---

## 🔒 Security & Privacy Architecture

- **Manifest V3 Compliant**: Built strictly on modern Chrome Manifest V3 standards with service workers and zero obsolete background pages.
- **Minimal Permissions Principle**:
  - `activeTab`: Only requests access to the active tab's URL when the user explicitly clicks the extension icon. No passive browsing history is monitored or stored.
  - `storage`: Retains user configuration (API base URL, risk thresholds) and local scan history entirely inside the user's local browser profile.
- **Zero Hardcoded Secrets**: No API keys or sensitive backend credentials exist in client-side extension bundles; all intelligence queries route through the authenticated backend correlation engine.
- **URL Sanitization**: Strips sensitive query parameters, UTM tags, auth tokens, and session identifiers before backend transmission.

---

## ⚙️ Extension Settings

Click the **Gear icon** in the popup header to customize:
- **Risk Radar API Base**: Default `http://localhost:5000/api` (can be configured to a remote cloud or enterprise deployment).
- **High-Risk Threshold**: Configure the score boundary (default: `60`) at which the critical alert banner triggers.
