# VAST - Volatile Artifact Snapshot Triage
## ICT3215 Digital Forensics Project

## Overview

VAST automates forensic analysis of VM snapshots. Upload a VMware (.vmem) or VirtualBox (.sav) file and get a comprehensive security report with threat detection, process analysis, and network monitoring.

## Setup

```bash
# 1. Clone repository
git clone https://github.com/khrnrn/VAST.git
cd VAST

# 2. Install Volatility 3
pip install volatility3

# 3. Done! Run your first analysis
python vast.py --input test.vmem --os windows
```

## Basic Usage

**One command, complete analysis:**
```bash
python vast.py --input snapshot.vmem --os windows
```

**Results saved to:**
```
output/YYYYMMDD_HHMMSS/
├── raw/                    # Converted memory dump
├── extracted_memory/       # Processes & network
├── extracted_files/        # Files & registry
├── enhanced/               # Threat-scored data
└── reports/
    ├── automated_analysis.txt    # Human-readable report
    └── vast_report.json          # Machine-readable data
```

**Read the report:**
```bash
cat output/*/reports/automated_analysis.txt
```

## Advanced Usage

### Run Step-by-Step

Useful for debugging or testing individual components:

```bash
# Create session folder
SESSION="output/my_case"

# Step 1: Parse snapshot → raw memory
python parser.py test.vmem --session $SESSION

# Step 2: Extract processes & network
python memory_extractor.py $SESSION/raw/snapshot_*.raw --session $SESSION

# Step 3: Extract files & registry
python file_extractor.py $SESSION/raw/snapshot_*.raw --session $SESSION

# Step 4: Add threat scoring
python artifact_enhancer.py $SESSION/extracted_memory/snapshot_*_memory.json --session $SESSION
python artifact_enhancer.py $SESSION/extracted_files/snapshot_*_file_activity.json --session $SESSION

# Step 5: Generate analysis report
python automated_analysis.py \
    $SESSION/raw/snapshot_*.raw \
    $SESSION/extracted_memory/snapshot_*_memory.json \
    $SESSION/extracted_files/snapshot_*_file_activity.json \
    --session $SESSION
```

### Options

```bash
# Fast mode (skip threat analysis)
python vast.py --input test.vmem --skip-enhance

# Compare with baseline
python vast.py --input test.vmem --baseline clean_system.json

# Custom threat indicators
python vast.py --input test.vmem --ioc my_iocs.json
```

## What You Get

**Automated Analysis Report includes:**
- Computer name and user accounts
- Running processes with MITRE ATT&CK detection
- Network connections (internal & external)
- Suspicious file locations
- Persistence mechanisms
- Threat severity scoring (HIGH/MEDIUM/LOW)

**Sample Report:**
```
================================================================================
VAST AUTOMATED FORENSIC ANALYSIS REPORT
================================================================================

SYSTEM INFORMATION
Computer Name: WORKSTATION-01
Users Found: admin, analyst

EXECUTIVE SUMMARY
Total Processes: 87
Suspicious Processes: 2
Shell/Script Processes: 5

Total Network Connections: 23
External Connections: 8
Suspicious Connections: 1

THREAT ASSESSMENT
Total Findings: 3
  HIGH Severity: 1
  MEDIUM Severity: 2

MITRE ATT&CK TECHNIQUES OBSERVED
  T1059 - Command & Scripting Interpreter
  T1218 - Signed Binary Proxy Execution

PROCESS RED FLAGS
  powershell.exe running from non-standard path: C:\Users\admin\AppData\Local\Temp
  suspicious.exe using encoded PowerShell commands

NETWORK ANOMALIES
  External connection to 185.220.101.45:4444
  [CRITICAL] Connection to suspicious C2 port: 4444
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `python vast.py --input <file>` | Full automated analysis |
| `python parser.py <file> --session <dir>` | Convert snapshot to raw memory |
| `python memory_extractor.py <raw> --session <dir>` | Extract processes/network |
| `python file_extractor.py <raw> --session <dir>` | Extract files/registry |
| `python artifact_enhancer.py <json> --session <dir>` | Add threat scoring |
| `python automated_analysis.py <raw> <mem> <file> --session <dir>` | Generate report |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "vol.py not found" | Ensure vol.py exists in project root |
| "Volatility plugin failed" | Run `python vol.py --help` to verify installation |
| "No artifacts extracted" | Memory dump may be corrupted or incompatible |
| Enhancement fails | Use `--skip-enhance` flag (enhancement is optional) |

## Practical Examples

**Incident Response:**
```bash
# Analyze suspicious system
python vast.py --input incident.vmem --os windows

# Find high-severity threats
grep "HIGH" output/*/reports/automated_analysis.txt

# Check suspicious processes
cat output/*/enhanced/*_memory_enriched.json | jq '.processes[] | select(.suspicious_score > 5)'
```

**Baseline Comparison:**
```bash
# Capture clean system baseline
python vast.py --input clean.vmem --os windows
mv output/*/extracted_memory/*_memory.json baseline.json

# Compare infected system
python vast.py --input infected.vmem --baseline baseline.json
```

**CTF / Lab Work:**
```bash
# Quick analysis
python vast.py --input challenge.vmem --os windows

# Answer questions from report
grep "Computer Name" output/*/reports/automated_analysis.txt
grep "Total Processes" output/*/reports/automated_analysis.txt
```

## Performance

| Memory Dump Size | Analysis Time |
|-----------------|---------------|
| 256MB | 2 minutes |
| 1GB | 6 minutes |
| 4GB | 20 minutes |

## Team

- **Khairunnurrin Zurain** - Integration & Testing
- **Nur Nabilah** - Reporting & Visualization  
- **Amelia Marzuki** - File Extraction
- **Muhammad Solikhin** - Snapshot Parser
- **Mustaq Yunos** - Memory Extraction

**Course:** ICT3215 Digital Forensics, Singapore Institute of Technology

**Repository:** https://github.com/khrnrn/VAST