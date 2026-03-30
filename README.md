# 🛡️ Hybrid ML IDS — No Docker Setup

Runs natively on Windows with Python venv. No Docker required.

## Quick Start (Windows)

### 1. Install Python 3.11+
Download from https://python.org — check "Add to PATH" during install.

### 2. Clone repo
```
git clone https://github.com/Vikrant892/ids-project.git
cd ids-project
```

### 3. Run setup (one time only)
```
setup.bat
```
This creates a venv, installs all dependencies, and initialises the database.

### 4. Generate test PCAP (for demo without live traffic)
```
generate_test_pcap.bat
```

### 5. Train ML models
```
train.bat
```
Takes 5–10 minutes. Auto-generates synthetic data if `data/raw/` is empty.
For real results, download CICIDS2017 CSVs → place in `data/raw/`.

### 6. Start IDS engine (Terminal 1)
```
start.bat
```
Processes PCAP by default. For live capture, run as Administrator.

### 7. Open dashboard (Terminal 2)
```
dashboard.bat
```
Opens at http://localhost:8501

### 8. Run tests
```
test.bat
```

---

## Project Structure
```
ids-project/
├── setup.bat              ← Run first (one time)
├── train.bat              ← Train ML models
├── start.bat              ← Start IDS engine
├── dashboard.bat          ← Open Streamlit dashboard
├── test.bat               ← Run all tests
├── generate_test_pcap.bat ← Make synthetic test PCAP
├── .env.example           ← Copy to .env and configure
├── requirements.txt
├── src/
│   ├── main.py            ← Entry point
│   ├── nids/              ← Packet capture, flow builder, signatures
│   ├── hids/              ← Log parser, FIM, process monitor
│   ├── ml/                ← Isolation Forest, Random Forest, Autoencoder, Ensemble
│   ├── alerts/            ← Alert manager, Email/Slack notifiers
│   ├── dashboard/         ← Streamlit app
│   └── utils/             ← Config, DB, logging
├── tests/
│   ├── unit/
│   ├── integration/
│   └── simulation/
├── data/
│   ├── raw/               ← Place CICIDS2017 CSVs here
│   ├── pcap/              ← PCAP files for testing
│   └── baselines/         ← FIM hash baselines
├── db/                    ← SQLite database
└── logs/                  ← Structured JSON logs
```

---

## Free Hosting (Dashboard)

Deploy dashboard to Streamlit Cloud:
1. Push to GitHub
2. Go to https://share.streamlit.io
3. New app → select repo → main file = `src/dashboard/app.py`
4. Add `.env` values as Secrets in the Streamlit Cloud UI
5. Deploy — get a public URL instantly

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `scapy` install fails | Run: `pip install scapy --pre` |
| Live capture permission denied | Run `start.bat` as Administrator |
| `No module named src` | Run from inside `ids-project\` folder |
| Models not found | Run `train.bat` first |
| Port 8501 in use | Edit `dashboard.bat` — change `--server.port=8501` to `8502` |
| Torch install slow | Normal — PyTorch is 2GB. Wait it out. |

---

## MITRE ATT&CK Coverage
T1046 Port Scan · T1499 SYN Flood · T1498 ICMP Flood · T1498.002 DNS Amplification
T1071 C2 Ports · T1190 Sensitive Port Access · T1110 Brute Force · T1110.001 SSH BF
T1548.003 Sudo Abuse · T1136 Account Creation · T1565 File Tampering · T1059 Shell Spawn
