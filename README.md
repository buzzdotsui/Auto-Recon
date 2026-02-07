# 🔍 AutoRecon

**Continuous Security Monitoring & Vulnerability Scanner**

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Tools-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Status-Active-green?style=for-the-badge)

## 🚀 Overview

AutoRecon is a Python-based **security surveillance tool** that periodically scans your infrastructure to detect unauthorized changes. It functions as a "digital CCTV" for your network perimeter.

### 🛡️ Key Features

- ** Automated Nmap Scans:** Runs targeted scans on defined subnets.
- ** Baselining:** Compares current scan results against a known "good" state.
- ** Drift Detection:** Insantly alerts on newly opened ports or changed service versions.
- ** XML Parsing:** Custom logic to extract actionable data from scan artifacts.

## 📦 Usage

### 1. Configure Target
Edit `config.yaml` to define your target IP ranges.

### 2. Run Initial Baseline
```bash
python src/scanner.py --baseline
```

### 3. Start Monitoring
Add to crontab for hourly checks:
```bash
0 * * * * cd /opt/autorecon && python src/main.py
```

## 🏗️ Logic Flow

```mermaid
sequenceDiagram
    participant Cron
    participant Scanner
    participant Differ
    participant AlertSystem
    
    Cron->>Scanner: Trigger Scan
    Scanner->>Scanner: Run Nmap (XML Output)
    Scanner->>Differ: Pass New XML
    Differ->>Differ: Compare with Baseline XML
    alt New Port Found
        Differ->>AlertSystem: Trigger Alert (Slack/Email)
        AlertSystem-->>Admin: "New Port 22 Open on DB-01!"
    else Unchanged
        Differ->>Log: Log "Clean Scan"
    end
```

## 📄 License

[MIT](https://choosealicense.com/licenses/mit/)
