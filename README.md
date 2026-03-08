# 🛡️ AI-Powered Next-Generation Firewall (NGFW)

A **high-performance, Windows-exclusive** Next-Generation Firewall integrating Layer 3/4 packet filtering, Layer 7 Deep Packet Inspection (DPI), ML-based ransomware detection, and a real-time React monitoring dashboard.

---

## ✨ Features

### 🔥 Phase 1 — Core Firewall Engine
- **WinDivert Packet Capture** — Real-time interception of live network traffic.
- **Stateful Connection Tracking** — Monitors active connection states.
- **L3/L4 Rule Engine** — Configurable allow/drop/log rules by IP, protocol, and port.
- **NAT Engine** — Network Address Translation support.
- **Pipeline Architecture** — Modular packet processing pipeline.

### 🔍 Phase 2 — Deep Packet Inspection (DPI)
An 8-layer DPI engine for enterprise-grade traffic analysis:
- **Application Identification** — Fingerprint-based app detection (HTTP, DNS, TLS, SSH, etc.)
- **TLS/SSL Inspector** — Extracts SNI, certificate info, and TLS version.
- **IPS Engine** — Intrusion Prevention with signature-based threat detection.
- **Threat Intelligence** — Real-time IP/domain reputation checks.
- **Anomaly Detection** — Behavioral analysis for unusual traffic patterns.
- **File Type Detection** — Identifies file types in network streams.
- **Protocol Normalizer** — Normalizes traffic for consistent inspection.
- **TCP Reassembly** — Full TCP stream reassembly for payload analysis.

### 🤖 Phase 3 — ML-Based Ransomware Detection
- **Random Forest Classifier** trained on 50K+ malware samples.
- **99.33% Accuracy** | **0.9994 AUC** | **< 0.7% FPR**.
- SMOTE-Tomek for imbalanced data handling.
- **LIME** explainability for model predictions.
- **FastAPI** backend serving real-time predictions via REST API.

### 📊 Real-Time Dashboard
- Built with **React 19 + Vite + Recharts**.
- Live traffic monitoring, rule management, security alerts, and threat analytics.

---

## 🏗️ Project Structure

```
AI-powered---NextGenerationFirewall/
│
├── app/                         # Core firewall application
│   ├── core/                    # Packet capture, rules, connections, NAT, pipeline
│   ├── dpi/                     # 8-layer Deep Packet Inspection engine
│   └── TCP_Reassemble/          # TCP stream reassembly module
│
├── config/                      # Configuration files
│   ├── firewall_rules.json      # L3/L4 rule definitions
│   ├── app_signatures.json      # Application fingerprint database
│   └── nat_rules.json           # NAT rules
│
├── phase-3/                     # ML ransomware detection
│   ├── backend/                 # FastAPI prediction server
│   ├── Ransomware.ipynb         # Model training notebook
│   └── Photos/                  # Confusion matrix, LIME plots
│
├── ngfw-dashboard/              # React + Vite monitoring dashboard
│   └── src/
│       ├── components/          # Reusable UI components
│       └── pages/               # Dashboard, Live Packets, Malware Scanner, etc.
│
├── data/                        # Dataset directory (see data/README.md)
├── models/                      # Trained models (see models/README.md)
├── tests/                       # Test scripts
├── main.py                      # Firewall entry point
├── run.py                       # Application runner
├── requirements.txt             # Python dependencies
└── .gitignore
```

---

## 🖥️ Platform Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10/11 or Windows Server (64-bit) |
| **Driver** | WinDivert (auto-handled by `pydivert`) |
| **Python** | 3.10+ |
| **Node.js** | 18+ (for dashboard) |

> ⚠️ **Linux/macOS are NOT supported** — uses the Windows-specific WinDivert driver.

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/asfiyaaaa/AI-powered---NextGenerationFirewall.git
cd AI-powered---NextGenerationFirewall
```

### 2. Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run the Firewall (Administrator Required)
```powershell
python main.py
```

**Mock Mode** (no WinDivert driver needed — safe for testing):
```powershell
python main.py --test
```

### 4. Run the ML Prediction Server
```powershell
cd phase-3/backend
pip install -r ../requirements.txt
uvicorn main:app --reload
```

### 5. Run the Dashboard
```powershell
cd ngfw-dashboard
npm install
npm run dev
```

---

## 📦 Dataset & Models

Due to GitHub's file size limitations, **datasets and trained models are not included** in this repository.

- **Dataset**: See [`data/README.md`](data/README.md) for download instructions.
- **Models**: See [`models/README.md`](models/README.md) to train models locally.

---

## 🧪 Testing

```powershell
pytest                          # Unit tests
python test_security.py         # Security tests
python test_reassembly_demo.py  # TCP reassembly tests
```

---

## 🔧 Tech Stack

| Layer | Technology |
|---|---|
| Packet Capture | `pydivert` (WinDivert) |
| Core Engine | Python, Threading |
| DPI Engine | Custom protocol analyzers |
| ML Model | Scikit-learn (Random Forest), LIME |
| ML API | FastAPI, Uvicorn |
| Database | SQLite |
| Dashboard | React 19, Vite, Recharts |
| Config | JSON, YAML, Pydantic |

---

## 📄 License

This project is for educational and research purposes.
