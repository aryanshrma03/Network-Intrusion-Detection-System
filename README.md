# 🛡️ Network Intrusion Detection System

A defensive, explainable **Network Intrusion Detection System (NIDS)** built in Python. It analyzes network-flow metadata and identifies suspicious behavior using configurable detection rules and a lightweight anomaly score.

The project is designed as a safe cybersecurity portfolio application: it detects and analyzes traffic metadata but does not exploit systems, launch attacks, or generate malicious traffic.

## 🎯 Detection Capabilities

The default engine identifies signals including:

- Port scanning behavior
- Excessive connection attempts
- SYN-heavy connection patterns
- ICMP burst activity
- Unusual destination-port diversity
- Repeated connections to the same destination
- Suspicious privileged-port activity
- High-volume flow bursts

Each event receives:

```text
Risk Score: 0–100
Severity: NORMAL / LOW / MEDIUM / HIGH / CRITICAL
Detection Reasons: Explainable rules
```

## 🧠 Architecture

```text
Network Flow Metadata
        │
        ▼
Flow Parser / Simulator
        │
        ▼
Sliding-Window Detection Engine
        │
        ├── Port Scan Rules
        ├── SYN Burst Rules
        ├── ICMP Burst Rules
        ├── Connection Rate Rules
        └── Destination Diversity
                │
                ▼
        Risk Scoring Engine
                │
                ▼
       Alert + Dashboard
```

## 🚀 Features

- 🛡️ Rule-based NIDS engine
- 📈 0–100 risk scoring
- 🚦 Normal / Low / Medium / High / Critical
- 🔍 Explainable detection reasons
- 🔌 TCP/UDP/ICMP flow support
- 🎯 Port-scan detection
- ⚡ Connection-rate detection
- SYN-burst detection
- 📡 ICMP burst detection
- 📊 Live-style statistics dashboard
- 🧪 Built-in normal/suspicious traffic simulator
- 📂 CSV flow-log analysis
- 🖥️ CustomTkinter GUI
- 🧩 Modular architecture
- 🧪 Unit tests

## 🔒 Safety

This repository is a **defensive detector**.

It does not:

- Exploit hosts
- Scan arbitrary networks
- Generate attack traffic
- Perform credential attacks
- Bypass security controls
- Execute payloads

The included simulator generates synthetic flow records locally, while CSV analysis works on previously captured flow metadata.

## 📂 Project Structure

```text
Network-Intrusion-Detection-System/
│
├── data/
│   └── README.md
│
├── reports/
│   └── .gitkeep
│
├── src/
│   ├── main.py
│   ├── app/
│   │   ├── __init__.py
│   │   └── gui.py
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── events.py
│   │   └── engine.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── csv_reader.py
│   ├── simulator/
│   │   ├── __init__.py
│   │   └── scenarios.py
│   ├── components/
│   │   ├── __init__.py
│   │   ├── header.py
│   │   ├── controls.py
│   │   ├── risk_meter.py
│   │   └── event_log.py
│   └── config/
│       ├── __init__.py
│       └── theme.py
│
├── tests/
├── .gitignore
├── requirements.txt
└── README.md
```

## 📦 Installation

```bash
git clone https://github.com/aryanshrma03/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System

python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install:

```bash
pip install -r requirements.txt
```

## ▶️ Run

```bash
python src/main.py
```

The dashboard supports:

- Normal traffic simulation
- Suspicious traffic simulation
- CSV flow-log analysis
- Detection reset
- Alert log viewing

## 📄 CSV Input

The CSV reader accepts these columns:

```text
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flags,bytes
```

Example:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flags,bytes
2026-08-15T10:00:00,10.0.0.5,10.0.0.10,40122,443,TCP,ACK,1240
2026-08-15T10:00:01,10.0.0.5,10.0.0.10,40123,443,TCP,ACK,980
```

The application analyzes metadata only.

## 🧪 Detection Rules

### Port Scan

Triggers when a source contacts many distinct destination ports within the sliding window.

### SYN Burst

Detects unusually high numbers of SYN-only TCP flows.

### ICMP Burst

Detects unusually high ICMP flow frequency.

### Connection Rate

Flags a source producing a large number of flows inside a short time window.

### Destination Diversity

Flags a source communicating with many unique destination addresses in a short interval.

### Privileged-Port Activity

Adds risk when a source rapidly targets multiple low-numbered service ports.

## 📊 Severity

```text
0–19     NORMAL
20–39    LOW
40–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

The thresholds and rule weights can be modified in:

```text
src/detector/engine.py
```

## ⚠️ Limitations

A rule-based NIDS can generate false positives.

Legitimate activity such as:

- Vulnerability scanners
- Monitoring systems
- Backup systems
- Service discovery
- Load testing
- Large distributed applications

may resemble suspicious behavior.

Production NIDS deployments should correlate multiple signals and use context such as asset identity, baseline behavior, authentication logs, DNS, endpoint telemetry, and threat intelligence.

## 🔮 Future Improvements

- [ ] PCAP ingestion
- [ ] Zeek log ingestion
- [ ] Suricata EVE JSON ingestion
- [ ] SQLite alert history
- [ ] Real-time charts
- [ ] JSON/CSV report export
- [ ] Rule configuration file
- [ ] Machine-learning anomaly detection
- [ ] IP reputation enrichment
- [ ] Alert deduplication
- [ ] MITRE ATT&CK mapping
- [ ] SOC-style incident timeline
- [ ] Email/webhook notifications

## 👨‍💻 Author

**Aryan Sharma**

Cybersecurity-focused Python project demonstrating defensive network monitoring, explainable intrusion detection, and security-event analysis.
