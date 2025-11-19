# ICT3215 Digital Forensics Project
## VAST - Volatile Artifact Snapshot Triage

## 📌 Overview

VAST (Volatile Artifact Snapshot Triage) is a digital forensic tool designed to extract volatile artifacts directly from virtual machine snapshots. Unlike traditional forensic tools that require converting snapshots into raw memory dumps, VAST automates this process — providing investigators with a faster and more reliable way to analyze evidence from VMware (.vmsn, .vmem) and VirtualBox (.sav) environments.
VAST identifies critical forensic artifacts such as:
* Active and terminated processes
* Open network connections
* Registry and configuration remnants
* Recently accessed files and volatile system data

This tool enables investigators to reconstruct a system’s state at the exact moment a VM snapshot was captured — bridging the gap between physical memory forensics and modern virtualized infrastructures.

## 🚀 Features
* Direct Snapshot Parsing → Reads VMware and VirtualBox snapshot formats without requiring external conversion tools.
* Volatile Artifact Extraction → Automatically retrieves key evidence: running processes, network sessions, memory-resident credentials.
* Automated Triage Reports → Generates structured JSON/HTML timelines for incident responders.
* Cross-Platform Support → Compatible with major hypervisors (VMware, VirtualBox).
* Forensic Accuracy → Validated against Volatility and Rekall outputs to ensure reliability.

## 🏗️ System Design
* Stage 1 — Parsing: Decompress and isolate guest memory from snapshot formats (.sav, .vmsn, .vmem).
* Stage 2 — Artifact Extraction:
    * Kernel structure scanning for running processes.
    * Pool tag analysis for open network connections.
    * Regex and entropy filters for secrets or credentials.
* Stage 3 — Reporting: Correlate extracted artifacts into JSON-based timelines with confidence scores.

## Installation & Usage
```
# clone the repository
git clone https://github.com/khrnrn/VAST.git
cd VAST

# install dependencies
pip install volatility3

# run VAST on a snapshot file
python parser.py "/path/to/snapshot.vmem or .sav"
python Memory_extractor.py "/path/to/raw"
python Artifact_enhancer.py "/path/to/json"
python vast.py --input /path/to/snapshot.vmsn --os windows --output report.json
```

## 🧩 Example Use Case
* Scenario: An enterprise detects suspicious activity in a virtualized environment.
* Solution: VAST parses a VMware snapshot (.vmsn), extracts the list of active processes, and highlights a suspicious PowerShell session with an external IP connection — pinpointing the exact moment of compromise.

## 📊 Validation
* Compared extracted artifacts with Volatility Framework outputs.
* Tested on VirtualBox (.sav) and VMware (.vmsn) snapshots.
* Benchmarked for accuracy, performance, and reliability in simulated forensic cases.


## 👥 Team
* Khairunnurrin Zurain Binte Khairon Jazan 
* Nur Nabilah Binte Zainal 
* Amelia Binte Marzuki 
* Muhammad Solikhin 
* Mustaq Yunos 
