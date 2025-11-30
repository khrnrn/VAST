# VAST - Volatile Artifact Snapshot Triage
## ICT3215 Digital Forensics Project

## Overview

VAST automates forensic analysis of VM snapshots through an interactive web dashboard. Upload a VMware (.vmem/.vmsn) snapshot and get a comprehensive security report with threat detection, process analysis, and network monitoring.

## Quick Start
```bash
# 1. Clone repository
git clone https://github.com/khrnrn/VAST.git
cd VAST

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch dashboard
streamlit run dashboard.py
```

That's it! Your browser will open to `http://localhost:8501`

## Using the Dashboard

### 1. Upload Snapshot
- **Windows**: Upload `.vmem` file
- **Linux/macOS**: Upload both `.vmem` AND `.vmsn` files (hold Ctrl/Cmd to select multiple)
- Select guest OS type (Windows/Linux/macOS)
- Choose extraction options (Processes, Network, Files, Registry)
- Click "Start Analysis"

### 2. View Results
Navigate through 4 tabs:
- **Timeline & Analysis**: Device info, search, executive summary, threat overview
- **Advanced Analytics**: 8 visualizations including port activity, threat distribution, connection states
- **Deep Forensics**: Process investigation, network forensics, system artifacts, threat indicators
- **Export**: Download JSON/text reports

## What You Get

**Snapshot Information:**
- Computer name and username
- OS version and architecture
- File size and analysis timestamp

**Automated Analysis:**
- Running processes with MITRE ATT&CK mapping
- Network connections (internal & external)
- Suspicious file locations
- Threat severity scoring (HIGH/MEDIUM/LOW)
- Process trees and parent-child relationships
- Port activity analysis

**Sample Dashboard Output:**
```
Snapshot Information
├─ Username: analyst
├─ Computer Name: WORKSTATION-01
├─ OS Version: Windows 10.0 (Build 19041)
└─ File Size: 4.13 GB

Threat Overview
├─ 🔴 High Risk: 2
├─ 🟡 Medium Risk: 5
├─ 🟢 Low Risk: 3
└─ ✅ Clean: 77

MITRE ATT&CK Techniques Observed
├─ T1059 - Command & Scripting Interpreter
└─ T1218 - Signed Binary Proxy Execution
```

## Supported File Formats

| OS | Required Files | Notes |
|---|---|---|
| Windows | `.vmem` | Single file upload |
| Linux | `.vmem` + `.vmsn` | Must have matching base names |
| macOS | `.vmem` + `.vmsn` | Must have matching base names |

**Maximum file size:** 100GB combined

## Features

✅ **Zero Configuration** - No command-line required  
✅ **Multi-OS Support** - Windows, Linux, macOS  
✅ **Real-time Progress** - See analysis stages as they run  
✅ **Interactive Search** - Filter across all artifacts  
✅ **Visual Analytics** - 8+ charts and graphs  
✅ **Export Reports** - JSON and text formats  
✅ **Device Identification** - Automatic username/hostname extraction  

## Analysis Pipeline (Automatic)

When you click "Start Analysis", VAST runs:

1. **Parse Snapshot** → Extract raw memory from VM files
2. **Memory Extraction** → Processes, network connections (10-30 min)
3. **File Extraction** → File objects, registry keys (10-30 min)
4. **Enhancement** → Add threat scores and MITRE mappings
5. **Report Generation** → Create human-readable analysis

All results saved to `output/YYYYMMDD_HHMMSS/`

## Advanced: Command Line (Optional)

If you prefer command-line or automation:
```bash
# Full automated analysis
python vast.py --input snapshot.vmem --os windows

# Read the report
cat output/*/reports/automated_analysis.txt
```

**Step-by-step (for debugging):**
```bash
SESSION="output/my_case"
python parser.py test.vmem --session $SESSION
python memory_extractor.py $SESSION/raw/snapshot_*.raw --session $SESSION
python file_extractor.py $SESSION/raw/snapshot_*.raw --session $SESSION
python artifact_enhancer.py $SESSION/extracted_memory/*.json --session $SESSION
python automated_analysis.py $SESSION/raw/*.raw $SESSION/extracted_memory/*.json $SESSION/extracted_files/*.json --session $SESSION
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Dashboard won't start | Run `pip install -r requirements.txt` |
| "Backend not configured" | Ensure `vast_integration.py` and `automated_analysis.py` are in same folder |
| File upload fails | Check file size < 100GB, correct file types |
| Analysis stuck | Large dumps (>8GB) can take 30-60 minutes |
| No data shown | Check session folder `output/YYYYMMDD_HHMMSS/` for JSON files |

## Performance

| Memory Dump Size | Analysis Time |
|-----------------|---------------|
| 256MB | 2-5 minutes |
| 1GB | 5-10 minutes |
| 4GB | 15-25 minutes |
| 8GB+ | 30-60 minutes |

## Requirements

- Python 3.8+
- Volatility 3
- Streamlit
- Plotly, Pandas

All installed via `pip install -r requirements.txt`

## Output Structure
```
output/YYYYMMDD_HHMMSS/
├── raw/                          # Converted memory dump
├── extracted_memory/             # Processes & network (JSON)
├── extracted_files/              # Files & registry (JSON)
├── enhanced/                     # Threat-scored data (JSON)
└── reports/
    ├── automated_analysis.txt    # Human-readable report
    ├── automated_analysis.json   # Machine-readable data
    └── vast_report_*.json        # Dashboard export
```

## Team

- **Khairunnurrin Zurain** - Integration & Testing
- **Nur Nabilah** - Reporting & Visualization  
- **Amelia Marzuki** - File Extraction
- **Muhammad Solikhin** - Snapshot Parser
- **Mustaq Yunos** - Memory Extraction

**Course:** ICT3215 Digital Forensics, Singapore Institute of Technology  
**Repository:** https://github.com/khrnrn/VAST

## License

Educational use only - ICT3215 Course Project