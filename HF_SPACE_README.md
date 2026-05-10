---
title: Hybrid ML Intrusion Detection System
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: true
license: other
short_description: Hybrid network + host IDS — IF + RF + Autoencoder ensemble, real-time Streamlit dashboard, MITRE ATT&CK mapping.
---

# Hybrid ML Intrusion Detection System

Live demo of a hybrid NIDS + HIDS that combines an Isolation Forest + Random Forest + Autoencoder ensemble with a deterministic signature engine, persists to SQLite, and surfaces alerts through a Streamlit dashboard.

> **Demo mode.** This Space runs in `DASHBOARD_DEMO_MODE=true`. Live packet capture is not possible inside a sandboxed Space (no host network access). The dashboard reads bundled sample alerts from `db/ids.sqlite` and accepts ad-hoc PCAP / CSV / log uploads via the **Upload & Analyse** tab for on-demand inference.

## What's behind it

- **NIDS pipeline** — Scapy capture → bidirectional 5-tuple flow builder → 24-feature flow vector → ensemble classifier → SQLite + multi-channel alerts.
- **HIDS pipeline** — file integrity monitoring (SHA-256), syslog/auth-log parser, psutil-based process anomaly detector.
- **ML ensemble** — Isolation Forest (200 trees, contamination 0.05), Random Forest (300 trees, balanced class weights), Autoencoder (24→64→32→8→32→64→24, MSE loss, percentile-calibrated threshold).
- **Dashboard** — Six-page Streamlit interface: Overview, Upload & Analyse, Alert Feed, ML Models, PCAP Inspector, Reports. Reads training-time `metrics.json` for honest benchmark numbers (no hardcoded marketing figures).
- **Forensics on upload** — DHCP/Kerberos/NTLM/LDAP/NetBIOS/HTTP decoders for Windows protocol fingerprinting from uploaded PCAPs.

## Repo

Source: [`Vikrant892/ids-project`](https://github.com/Vikrant892/ids-project)

Author: [Vikrant](https://vikrant69g.com)
