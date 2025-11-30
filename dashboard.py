# dashboard.py - VAST Memory Forensics Dashboard (MERGED v3.0)
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import os
import sys
from pathlib import Path
import tempfile

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from vast_integration import VASTAnalyzer, run_analysis
    BACKEND_AVAILABLE = True
except ImportError as e:
    st.error("Backend not found. Make sure vast_integration.py is in the same folder.")
    BACKEND_AVAILABLE = False

# Page config
st.set_page_config(page_title="VAST - Memory Forensics Dashboard", page_icon="", layout="wide")

# Custom CSS
st.markdown("""
<style>
    .big-font { font-size: 50px !important; font-weight: bold; }
    .info-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px; border-radius: 12px; margin: 10px 0; color: white; box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .stMetric { background-color: #1e1e1e; padding: 15px; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='big-font'> VAST - Volatile Artifact Snapshot Triage</div>", unsafe_allow_html=True)
st.markdown("**Advanced Memory Forensics Dashboard**")
st.markdown("---")

# Initialize session state
for key in ['analysis_complete', 'analysis_results', 'session_dir', 'search_query', 'os_type', 'snapshot_info']:
    if key not in st.session_state:
        st.session_state[key] = False if key == 'analysis_complete' else (None if key != 'search_query' else "")

# ========================
# METADATA EXTRACTION FUNCTION (FROM V2 - WORKING!)
# ========================
def extract_snapshot_metadata(display_results, automated_results=None):
    """Extract metadata for Windows, Linux, and macOS"""
    metadata = {
        'computer_name': 'Unknown',
        'username': 'Unknown',
        'os_version': 'Unknown',
        'architecture': 'Unknown',
        'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'filename': 'N/A',
        'size_gb': 'N/A',
        'os_type': 'Unknown'
    }

    if not automated_results:
        return metadata

    sys_info = automated_results.get("system_info", {})

    # === COMPUTER NAME ===
    metadata['computer_name'] = sys_info.get("computer_name") or sys_info.get("hostname", "Unknown")

    # === ARCHITECTURE ===
    if sys_info.get("architecture"):
        metadata['architecture'] = sys_info["architecture"]
    elif "plugin_output" in sys_info:
        is64 = next((item['Value'] for item in sys_info["plugin_output"] if item['Variable'] == 'Is64Bit'), None)
        metadata['architecture'] = "x64" if is64 == "True" else "x86"
    elif sys_info.get("Is64Bit") is not None:
        metadata['architecture'] = "x64" if sys_info["Is64Bit"] else "x86"

    # === USERNAME (SMART FILTERING) ===
    usernames = []
    if sys_info.get("usernames"):
        usernames = sys_info["usernames"]
    elif "plugin_output" in sys_info:
        uname_line = next((item['Value'] for item in sys_info["plugin_output"] if "login name" in str(item.get('Variable', '')).lower()), None)
        if uname_line:
            usernames = [uname_line]

    # Filter out system accounts
    system_accounts = {
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
        "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
        "systemd-network", "systemd-resolve", "messagebus", "_apt",
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "Administrator"
    }
    real_users = [u for u in usernames if not u.endswith('$') and u not in system_accounts]

    if real_users:
        metadata['username'] = real_users[0]
    else:
        # Fallback: parse from process paths
        for p in display_results.get("processes", []):
            path = str(p.get("ImagePath") or p.get("ImageFileName") or p.get("comm", "") or "")
            path = path.lower()
            if "/home/" in path:
                username = path.split("/home/")[1].split("/")[0]
                if username and username not in ["", "root"]:
                    metadata['username'] = username
                    break
            elif "\\users\\" in path:
                parts = path.split("\\users\\")
                if len(parts) > 1:
                    username = parts[1].split("\\")[0]
                    if username not in ["public", "default", "all users"]:
                        metadata['username'] = username.capitalize()
                        break

    # === OS VERSION ===
    plugin_output = sys_info.get("plugin_output", [])

    # Windows
    if any("NtMajorVersion" in str(item.get('Variable', '')) for item in plugin_output):
        nt_major = next((item['Value'] for item in plugin_output if item['Variable'] == 'NtMajorVersion'), '10')
        nt_minor = next((item['Value'] for item in plugin_output if item['Variable'] == 'NtMinorVersion'), '0')
        build = next((item['Value'].split('.')[1] for item in plugin_output if item['Variable'] == 'Major/Minor'), 'Unknown')
        metadata['os_version'] = f"Windows {nt_major}.{nt_minor} (Build {build})"
        metadata['os_type'] = "Windows"

    # Linux
    elif any("Linux version" in str(item.get('Value', '')) for item in plugin_output):
        version_line = next((item['Value'] for item in plugin_output if "Linux version" in str(item.get('Value', ''))), "")
        if version_line:
            metadata['os_version'] = version_line.split(" ")[2] if len(version_line.split()) > 2 else version_line
        else:
            os_release = next((item['Value'] for item in plugin_output if "PRETTY_NAME" in str(item.get('Value', ''))), "")
            metadata['os_version'] = os_release.strip('"')
        metadata['os_type'] = "Linux"

    # macOS
    elif any("Darwin Kernel" in str(item.get('Value', '')) for item in plugin_output):
        kernel_line = next((item['Value'] for item in plugin_output 
                        if "Darwin Kernel" in str(item.get('Value', ''))), "")
        if kernel_line:
            metadata['os_version'] = kernel_line.strip()
        metadata['os_type'] = "macOS"

    # Fallback
    if metadata['os_version'] == 'Unknown':
        summary = display_results.get("summary", {})
        if summary.get("os_version"):
            metadata['os_version'] = summary["os_version"]

    return metadata

def generate_json_report(results):
    return json.dumps({
        'metadata': {'date': datetime.now().isoformat(), 'tool': 'VAST v3.0',
                    'os': st.session_state.get('os_type', 'Unknown'),
                    'session': st.session_state.get('session_dir', 'N/A'),
                    'snapshot_info': st.session_state.get('snapshot_info', {})},
        'summary': results.get('summary', {}),
        'artifacts': {'processes': results.get('processes', []),
                     'connections': results.get('connections', []),
                     'files': results.get('file_objects', [])}
    }, indent=2)

# ========================
# TABS
# ========================
tab1, tab2, tab3, tab4 = st.tabs(["Upload Snapshot", "Timeline & Analysis", "Advanced Analytics", "Deep Forensics"])

with tab1:
    st.header("Upload VM Snapshot")
    
    # OS Selection FIRST (before file upload)
    os_type = st.selectbox("Guest OS", ["Windows", "Linux", "macOS"], index=0, 
                          help="Select the operating system of the memory snapshot")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        # Clear instructions for multiple file upload
        if os_type == "Linux":
            st.info("**Linux requires 2 files:** Select both .vmem AND .vmsn files (hold Cmd/Ctrl to select multiple)")
        elif os_type == "macOS":
            st.info("**macOS:** Upload .vmem, .raw, or .sav file")
        
        uploaded_files = st.file_uploader(
            "Choose snapshot file(s)" if os_type != "Linux" else "Choose BOTH .vmem and .vmsn files",
            type=['vmem', 'vmsn', 'sav', 'raw', 'gz'],
            help="For Linux: Upload BOTH .vmem and .vmsn files | For Windows/macOS: Upload .vmem, .raw, or .sav file",
            accept_multiple_files=True  # Enable multiple file upload
        )

        if uploaded_files:
            st.markdown("### Uploaded Files:")
            total_size = 0
            
            # Display each uploaded file clearly
            for idx, uploaded_file in enumerate(uploaded_files, 1):
                size_gb = uploaded_file.size / (1024**3)
                size_str = f"{size_gb:.2f} GB" if size_gb >= 1 else f"{uploaded_file.size / (1024**2):.1f} MB"
                total_size += uploaded_file.size
                
                # Color-code by file type
                if uploaded_file.name.endswith('.vmem'):
                    st.success(f"{idx}. {uploaded_file.name} - {size_str} (Memory dump)")
                elif uploaded_file.name.endswith('.vmsn'):
                    st.info(f"{idx}. {uploaded_file.name} - {size_str} (Snapshot metadata)")
                elif uploaded_file.name.endswith('.raw'):
                    st.success(f"{idx}. {uploaded_file.name} - {size_str} (Raw memory)")
                else:
                    st.write(f"{idx}. {uploaded_file.name} - {size_str}")
            
            # Show total size
            total_gb = total_size / (1024**3)
            total_str = f"{total_gb:.2f} GB" if total_gb >= 1 else f"{total_size / (1024**2):.1f} MB"
            st.markdown(f"**Total size:** {total_str}")
            
            # Warning for large files
            if total_gb > 100:
                st.error(f"Combined files too large: {total_str} (Max: 100GB)")
            elif total_gb > 5:
                st.warning(" Large files detected - analysis may take 15-20 minutes")
            
            # Linux-specific validation
            if os_type == "Linux":
                vmem_files = [f for f in uploaded_files if f.name.endswith('.vmem')]
                vmsn_files = [f for f in uploaded_files if f.name.endswith('.vmsn')]
                
                if vmem_files and vmsn_files:
                    vmem_base = vmem_files[0].name.rsplit('.', 1)[0]
                    vmsn_base = vmsn_files[0].name.rsplit('.', 1)[0]
                    
                    if vmem_base == vmsn_base:
                        st.success(f" File names match: {vmem_base}")
                    else:
                        st.error(f" File name mismatch! .vmem and .vmsn must have same base name")
                        st.write(f"   .vmem: {vmem_base}")
                        st.write(f"   .vmsn: {vmsn_base}")
                elif not vmsn_files:
                    st.warning(" Linux analysis requires both .vmem AND .vmsn files")

    with col2:
        st.markdown("**File Requirements:**")
        if os_type == "Linux":
            st.info("Linux needs both .vmem AND .vmsn files")
        elif os_type == "Windows":
            st.info("Windows needs .vmem or .raw file")
        else:
            st.info("macOS needs .vmem AND .vmsn  file")


    st.markdown("---")
    st.subheader("3. Analysis Options")
    c1, c2 = st.columns(2)
    with c1:
        extract_processes = st.checkbox(" Extract Processes", True, help="Extract running processes, PIDs, and process metadata")
        extract_network = st.checkbox(" Extract Network", True, help="Extract active connections, listening ports, and network activity")
    with c2:
        extract_files = st.checkbox(" Extract Files", True, help="Extract open file handles and file objects")
        extract_registry = st.checkbox(" Registry (Windows)", os_type == "Windows", help="Extract registry hives and activity (Windows only)")

    # Display what will be extracted
    selected_options = []
    if extract_processes:
        selected_options.append("Processes")
    if extract_network:
        selected_options.append("Network")
    if extract_files:
        selected_options.append("Files")
    if extract_registry and os_type == "Windows":
        selected_options.append("Registry")
    
    if selected_options:
        st.success(f" Will extract: {', '.join(selected_options)}")
    else:
        st.warning(" No extraction options selected!")

    st.markdown("---")
    
    col_btn1, col_btn2, _ = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button(" Start Analysis", type="primary", use_container_width=True):
            if not uploaded_files:
                st.error(" Upload file(s) first!")
            elif not BACKEND_AVAILABLE:
                st.error(" Backend not configured")
            elif total_gb > 100:
                st.error(" Files exceed 100GB limit")
            elif not any([extract_processes, extract_network, extract_files, extract_registry]):
                st.error(" Select at least one extraction option!")
            else:
                # Save all uploaded files to temp directory
                save_temp = Path(tempfile.gettempdir()) / "vast_uploads"
                save_temp.mkdir(exist_ok=True)
                
                saved_files = []
                for uploaded_file in uploaded_files:
                    tmp_path = save_temp / uploaded_file.name
                    with open(tmp_path, 'wb') as f:
                        f.write(uploaded_file.getvalue())
                    saved_files.append(tmp_path)
                    st.info(f"Saved: {uploaded_file.name}")
                
                # Use the primary file (.vmem or .raw) for analysis
                primary_file = None
                for f in saved_files:
                    if f.suffix.lower() in ['.vmem', '.raw', '.sav']:
                        primary_file = f
                        break
                
                if not primary_file:
                    st.error(" No valid memory dump found (.vmem, .raw, or .sav)")
                else:
                    try:
                        with st.spinner(" Analyzing..."):
                            progress = st.progress(0)
                            status = st.empty()
                        
                        def update(msg, prog):
                            status.text(msg)
                            progress.progress(prog)

                        # Prepare options dict
                        analysis_options = {
                            "extract_processes": extract_processes,
                            "extract_network": extract_network,
                            "extract_files": extract_files,
                            "extract_registry": extract_registry and os_type == "Windows"
                        }

                        # Display selected options
                        st.info(f" Extracting: {', '.join([k.replace('extract_', '').title() for k, v in analysis_options.items() if v])}")
                        
                        # Pass ALL saved files (including .vmsn) to run_analysis
                        results = run_analysis(saved_files, os_type.lower(), analysis_options, update)
                        
                        if results.get("success"):
                            analyzer = VASTAnalyzer()
                            display_results = analyzer.load_results(Path(results["session_dir"]))
                            
                            # Load automated results for metadata
                            automated_path = Path(results["session_dir"]) / "reports" / "automated_analysis.json"
                            automated_results = None
                            if automated_path.exists():
                                with open(automated_path) as f:
                                    automated_results = json.load(f)
                            
                            # Extract metadata using V2 function
                            snapshot_metadata = extract_snapshot_metadata(display_results, automated_results)
                            snapshot_metadata['filename'] = primary_file.name
                            snapshot_metadata['size_gb'] = f"{total_gb:.2f}"
                            snapshot_metadata['os_type'] = os_type
                            
                            st.session_state.analysis_results = display_results
                            st.session_state.raw_file_path = str(primary_file)
                            st.session_state.session_dir = results["session_dir"]
                            st.session_state.os_type = os_type
                            st.session_state.snapshot_info = snapshot_metadata
                            st.session_state.analysis_complete = True

                            status.empty()
                            progress.empty()
                            st.success(" Analysis Complete!")
                            st.info(" View results in Timeline & Advanced Analytics tabs")
                            st.balloons()
                        else:
                            st.error(" Analysis failed")
                    except Exception as e:
                        st.error(f" Error: {str(e)}")
                    finally:
                        # Cleanup saved files
                        for f in saved_files:
                            try:
                                f.unlink()
                            except:
                                pass
    
    with col_btn2:
        if st.button(" Clear", use_container_width=True):
            st.session_state.analysis_complete = False
            st.session_state.analysis_results = None
            st.session_state.snapshot_info = None
            st.rerun()

# ========================
# TAB 2: TIMELINE & ANALYSIS
# ========================
with tab2:
    if not st.session_state.analysis_complete:
        st.info(" **Upload and analyze a snapshot first**")
        st.markdown("### What VAST Does:")
        st.markdown("""
        - Automated VM snapshot parsing (no conversion needed)
        - Unified timeline correlation across all artifacts
        - AI-powered threat detection and scoring
        - Interactive visualizations and charts
        - MITRE ATT&CK technique mapping
        - Real-time search and filtering
        - Device and user identification
        """)
    else:
        results = st.session_state.analysis_results
        snapshot_info = st.session_state.snapshot_info or {}
        
        st.header(" Timeline & Forensic Analysis")
        
        # SNAPSHOT INFORMATION CARD
        st.markdown("### Snapshot Information")
        
        info_col1, info_col2, info_col3, info_col4 = st.columns(4)
        
        with info_col1:
            st.metric(" Username", snapshot_info.get('username', 'Unknown'))
        with info_col2:
            st.metric(" Computer Name", snapshot_info.get('computer_name', 'Unknown'))
        with info_col3:
            st.metric(" OS Version", snapshot_info.get('os_version', 'Unknown'))
        with info_col4:
            st.metric(" File Size", f"{snapshot_info.get('size_gb', 'N/A')} GB")
        
        with st.expander(" Full Snapshot Details", expanded=False):
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.markdown(f"**Filename:** {snapshot_info.get('filename', 'Unknown')}")
                st.markdown(f"**OS Type:** {snapshot_info.get('os_type', 'Unknown')}")
                st.markdown(f"**Architecture:** {snapshot_info.get('architecture', 'Unknown')}")
            with col_d2:
                st.markdown(f"**Analysis Time:** {snapshot_info.get('analysis_time', 'Unknown')}")
                st.markdown(f"**Session:** {Path(st.session_state.session_dir).name if st.session_state.session_dir else 'N/A'}")
        
        st.markdown("---")
        
        # SEARCH
        st.subheader(" Global Search")
        search_col1, search_col2 = st.columns([4, 1])
        
        with search_col1:
            search_query = st.text_input("", value=st.session_state.search_query,
                placeholder="Search across all artifacts...", label_visibility="collapsed")
            st.session_state.search_query = search_query
        
        with search_col2:
            if st.button("Clear", use_container_width=True):
                st.session_state.search_query = ""
                st.rerun()
        
        st.markdown("---")
        
        # SUMMARY
        st.subheader(" Executive Summary")
        
        procs = results.get('processes', [])
        conns = results.get('connections', [])
        files = results.get('file_objects', [])
        
        if search_query:
            procs = [p for p in procs if search_query.lower() in str(p).lower()]
            conns = [c for c in conns if search_query.lower() in str(c).lower()]
            files = [f for f in files if search_query.lower() in str(f).lower()]
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric(" Processes", len(procs))
        col2.metric(" Network", len(conns))
        col3.metric(" Files", len(files))
        col4.metric(" Total", len(procs) + len(conns) + len(files))
        
        if search_query:
            st.info(f" Showing {len(procs) + len(conns) + len(files)} results for '{search_query}'")
        
        st.markdown("---")
        
        # THREAT OVERVIEW
        st.subheader(" Threat Overview")
        
        procs_df = pd.DataFrame(procs) if procs else pd.DataFrame()
        if not procs_df.empty and "suspicious_score" in procs_df.columns:
            suspicious_procs = procs_df[procs_df["suspicious_score"] > 0]
            
            col_t1, col_t2, col_t3, col_t4 = st.columns(4)
            
            high_threat = len(suspicious_procs[suspicious_procs["suspicious_score"] >= 7])
            med_threat = len(suspicious_procs[(suspicious_procs["suspicious_score"] >= 4) & (suspicious_procs["suspicious_score"] < 7)])
            low_threat = len(suspicious_procs[suspicious_procs["suspicious_score"] < 4])
            
            col_t1.metric(" High Risk", high_threat)
            col_t2.metric("🟡 Medium Risk", med_threat)
            col_t3.metric("🟢 Low Risk", low_threat)
            col_t4.metric(" Clean", len(procs_df) - len(suspicious_procs))
        else:
            st.success(" No threats detected in this snapshot")
        
        st.markdown("---")
        
        # EVENT TIMELINE
        st.subheader("⏱️ Event Timeline")

        st.markdown("""
        <div style='background: linear-gradient(90deg, #1e3a8a 0%, #7c3aed 100%);
                    padding: 15px; border-radius: 10px; margin-bottom: 20px;'>
            <h4 style='color: white; margin: 0;'>📊 Chronological Event Sequence</h4>
        </div>
        """, unsafe_allow_html=True)

        timeline_events = []

        # Helper function to safely get process name
        def get_process_name(proc):
            """Extract process name with multiple fallback options"""
            name = (
                proc.get("ImageFileName") or 
                proc.get("comm") or 
                proc.get("COMM") or
                proc.get("name") or
                proc.get("Name") or
                None
            )
            
            if name and name != "Unknown":
                return str(name)
            
            # Last resort: check if there's any string value in the dict
            for key, value in proc.items():
                if isinstance(value, str) and value and len(value) > 0 and key.lower() in ['image', 'process', 'command', 'executable']:
                    return str(value)
            
            return "Unknown Process"

        # Helper function to safely get PID
        def get_pid(proc):
            """Extract PID with fallback options"""
            pid = proc.get('PID') or proc.get('pid') or proc.get('Pid')
            return pid if pid is not None else 'N/A'

        # Helper function to safely get PPID
        def get_ppid(proc):
            """Extract PPID with fallback options"""
            ppid = proc.get('PPID') or proc.get('ppid') or proc.get('Ppid')
            return ppid if ppid is not None else 'N/A'

        # Add processes to timeline
        for i, proc in enumerate(procs[:30]):
            if not isinstance(proc, dict):
                continue
            
            proc_name = get_process_name(proc)
            pid = get_pid(proc)
            ppid = get_ppid(proc)
            
            # Debug: Print first process to see structure
            if i == 0:
                st.info(f"🔍 Debug - First process keys: {list(proc.keys())}")
            
            timeline_events.append({
                'seq': i,
                'type': '⚙️ Process',
                'name': proc_name[:50],
                'details': f"PID: {pid} | PPID: {ppid}",
                'suspicious': proc.get('suspicious_score', 0),
                'time': f"Event #{i+1}"
            })

          # Add network connections to timeline
        offset = len(timeline_events)
        for i, conn in enumerate(conns[:30]):
            if not isinstance(conn, dict):
                continue
            
            local_addr = str(conn.get('LocalAddr', '0.0.0.0'))
            local_port = conn.get('LocalPort', 0)
            foreign_addr = str(conn.get('ForeignAddr', '0.0.0.0'))
            foreign_port = conn.get('ForeignPort', 0)
            proto = conn.get('Proto', 'TCP')
            state = conn.get('State', '')
            owner = conn.get('Owner', 'Unknown')
            
            # Determine display format based on connection type
            if foreign_addr in ['0.0.0.0', '::'] or not foreign_port:
                # Listening/Local connection
                display_name = f"Port {local_port}"
                details = f"{proto} | Listening on {local_addr}:{local_port} | Process: {owner}"
            else:
                # External connection
                display_name = f"{foreign_addr}:{foreign_port}"
                details = f"{proto} | {local_addr}:{local_port} → {foreign_addr}:{foreign_port}"
                if state:
                    details += f" | {state}"
                if owner and owner != 'Unknown':
                    details += f" | {owner}"
            
            timeline_events.append({
                'seq': offset + i,
                'type': '🌐 Network',
                'name': display_name,
                'details': details,
                'suspicious': conn.get('suspicious_score', 0),
                'time': f"Event #{offset+i+1}"
            })

        # Add files to timeline
        offset = len(timeline_events)
        for i, file in enumerate(files[:20]):
            if not isinstance(file, dict):
                continue
            
            file_name = (
                file.get("FileName") or 
                file.get("Name") or 
                file.get("path") or
                file.get("Path") or
                "Unknown File"
            )
            
            timeline_events.append({
                'seq': offset + i,
                'type': '📁 File',
                'name': str(file_name)[:50],
                'details': f"Offset: {file.get('Offset', file.get('offset', file.get('inode', 'N/A')))}",
                'suspicious': 0,
                'time': f"Event #{offset+i+1}"
            })

        # Display timeline cards
        if timeline_events:
            # Show debug info
            st.info(f"📊 Timeline generated: {len(timeline_events)} events ({len([e for e in timeline_events if e['type'] == '⚙️ Process'])} processes, {len([e for e in timeline_events if e['type'] == '🌐 Network'])} connections, {len([e for e in timeline_events if e['type'] == '📁 File'])} files)")
            
            for event in timeline_events[:50]: # Show first 50 events
                susp_badge = "🔴 HIGH RISK" if event['suspicious'] >= 7 else ("🟡 MEDIUM" if event['suspicious'] >= 4 else ("🟢 LOW" if event['suspicious'] > 0 else ""))
                
                with st.expander(f"{event['time']} - {event['type']}: {event['name']} {susp_badge}", expanded=False):
                    st.markdown(f"**Details:** {event['details']}")
                    if event['suspicious'] > 0:
                        st.warning(f"⚠️ Suspicion Score: {event['suspicious']}/10")
        else:
            st.info("No events to display in timeline")
        st.markdown("---")
        
        # PROCESS TABLE
        st.subheader("⚙️ Process Analysis")
        if procs:
            # Create clean dataframe
            procs_display = []
            for p in procs:
                if isinstance(p, dict):
                    procs_display.append({
                        'Process': get_process_name(p),
                        'PID': get_pid(p),
                        'PPID': get_ppid(p),
                        'Threads': p.get('Threads', p.get('threads', 'N/A')),
                        'User': p.get('User', p.get('user', p.get('uid', 'N/A'))),
                        'Suspicion': p.get('suspicious_score', 0)
                    })
            
            if procs_display:
                procs_df = pd.DataFrame(procs_display)
                
                with st.expander("📋 All Processes Table", expanded=False):
                    st.dataframe(procs_df, use_container_width=True, height=400)
                    st.download_button("💾 Download CSV", procs_df.to_csv(index=False), "processes.csv")
            else:
                st.warning("⚠️ Process data exists but couldn't be displayed. Check data format.")
        else:
            st.info("ℹ️ No process data available")
        
        st.markdown("---")
        
        # NETWORK TABLE
        st.subheader(" Network Analysis")
        if conns:
            conns_df = pd.DataFrame(conns)
            if '__children' in conns_df.columns:
                conns_df = conns_df.drop(columns=['__children'])
            
            with st.expander(" All Network Connections", expanded=False):
                st.dataframe(conns_df, use_container_width=True, height=400)
                st.download_button(" Download CSV", conns_df.to_csv(index=False), "connections.csv")

        st.markdown("---")

        # FILE TABLE
        st.subheader(" File Analysis")
        if files:
            files_df = pd.DataFrame(files)
            
            # remove volatile children column if present
            if '__children' in files_df.columns:
                files_df = files_df.drop(columns=['__children'])
            
            with st.expander(" All File Objects", expanded=False):
                st.dataframe(files_df, use_container_width=True, height=400)
                st.download_button(
                    " Download CSV",
                    files_df.to_csv(index=False),
                    "file_objects.csv"
                )
        else:
            st.info(" No file objects extracted")

# ========================
# TAB 3: ADVANCED ANALYTICS (ALL VISUALIZATIONS)
# ========================
with tab3:
    if not st.session_state.analysis_complete:
        st.info(" **Complete analysis first to view advanced analytics**")
    else:
        results = st.session_state.analysis_results
        snapshot_info = st.session_state.snapshot_info or {}
        
        st.header(" Advanced Analytics & Visualizations")
        
        # SNAPSHOT INFO AT TOP
        # st.markdown("### Device Information")
        # info_col1, info_col2, info_col3 = st.columns(3)
        # with info_col1:
        #     st.metric(" User", snapshot_info.get('username', 'Unknown'))
        # with info_col2:
        #     st.metric(" Device", snapshot_info.get('computer_name', 'Unknown'))
        # with info_col3:
        #     st.metric("🪟 OS", snapshot_info.get('os_version', snapshot_info.get('os_type', 'Unknown')))
        
        # st.markdown("---")
        
        procs = results.get('processes', [])
        conns = results.get('connections', [])
        files = results.get('file_objects', [])
        
        procs_df = pd.DataFrame(procs) if procs else pd.DataFrame()
        conns_df = pd.DataFrame(conns) if conns else pd.DataFrame()
        files_df = pd.DataFrame(files) if files else pd.DataFrame()
        
        # 1. PORT ACTIVITY ANALYSIS
        st.subheader(" Port Activity Analysis")
        
        col_p1, col_p2 = st.columns(2)
        
        with col_p1:
            if not conns_df.empty and 'LocalPort' in conns_df.columns:
                port_counts = conns_df['LocalPort'].value_counts().head(10)
                fig_ports = px.bar(
                    x=port_counts.index.astype(str),
                    y=port_counts.values,
                    title='Top 10 Most Active Ports',
                    labels={'x': 'Port Number', 'y': 'Connection Count'},
                    color=port_counts.values,
                    color_continuous_scale='Reds'
                )
                fig_ports.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_ports, use_container_width=True)
        
        with col_p2:
            if not conns_df.empty and 'Proto' in conns_df.columns:
                proto_counts = conns_df['Proto'].value_counts()
                fig_proto = px.pie(
                    values=proto_counts.values,
                    names=proto_counts.index,
                    title='Protocol Distribution',
                    color_discrete_sequence=px.colors.sequential.RdBu
                )
                fig_proto.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_proto, use_container_width=True)
        
        st.markdown("---")
        
        # 2. THREAT SEVERITY DISTRIBUTION
        st.subheader(" Threat Severity Distribution")
        
        if not procs_df.empty and 'suspicious_score' in procs_df.columns:
            suspicious_procs = procs_df[procs_df['suspicious_score'] > 0]
            
            if not suspicious_procs.empty:
                fig_threat = px.histogram(
                    suspicious_procs,
                    x='suspicious_score',
                    nbins=10,
                    title='Distribution of Suspicion Scores',
                    labels={'suspicious_score': 'Suspicion Score', 'count': 'Number of Processes'},
                    color_discrete_sequence=['#ef4444']
                )
                fig_threat.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_threat, use_container_width=True)
                
                st.markdown("#### Top 10 Most Suspicious Processes")
                top_suspicious = suspicious_procs.nlargest(10, 'suspicious_score')
                cols_to_show = []
                if 'ImageFileName' in top_suspicious.columns:
                    cols_to_show.append('ImageFileName')
                elif 'comm' in top_suspicious.columns:
                    cols_to_show.append('comm')
                if 'PID' in top_suspicious.columns:
                    cols_to_show.append('PID')
                elif 'pid' in top_suspicious.columns:
                    cols_to_show.append('pid')
                cols_to_show.extend(['suspicious_score'])
                if 'tags' in top_suspicious.columns:
                    cols_to_show.append('tags')
                st.dataframe(top_suspicious[cols_to_show], use_container_width=True)
            else:
                st.success(" No suspicious processes detected!")
        
        st.markdown("---")
        
        # 3. MEMORY USAGE DISTRIBUTION
        st.subheader(" Memory Usage Distribution")
        
        col_m1, col_m2 = st.columns(2)
        
        with col_m1:
            if not procs_df.empty and 'Threads' in procs_df.columns:
                st.markdown("#### Top 10 Thread Consumers")
                name_col = 'ImageFileName' if 'ImageFileName' in procs_df.columns else 'comm'
                pid_col = 'PID' if 'PID' in procs_df.columns else 'pid'
                top_threads = procs_df.nlargest(10, 'Threads')[[name_col, pid_col, 'Threads']].reset_index(drop=True)
                top_threads.index = top_threads.index + 1
                st.dataframe(top_threads, use_container_width=True)
            else:
                st.info("Thread data not available")
        
        
        st.markdown("---")
        
        # 4. CONNECTION STATE ANALYSIS
        st.subheader(" Connection State Analysis")
        
        if not conns_df.empty and 'State' in conns_df.columns:
            col_c1, col_c2 = st.columns(2)
            
            with col_c1:
                state_counts = conns_df['State'].value_counts()
                fig_states = px.bar(
                    x=state_counts.index,
                    y=state_counts.values,
                    title='Connection States',
                    labels={'x': 'State', 'y': 'Count'},
                    color=state_counts.values,
                    color_continuous_scale='Blues'
                )
                fig_states.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_states, use_container_width=True)
            
            with col_c2:
                if 'ForeignAddr' in conns_df.columns:
                    valid_addrs = conns_df[conns_df['ForeignAddr'].notna()]['ForeignAddr']
                    if not valid_addrs.empty:
                        top_ips = valid_addrs.value_counts().head(10)
                        fig_ips = px.bar(
                            x=top_ips.values,
                            y=top_ips.index,
                            orientation='h',
                            title='Top 10 External Connections',
                            labels={'x': 'Connection Count', 'y': 'IP Address'},
                            color=top_ips.values,
                            color_continuous_scale='Reds'
                        )
                        fig_ips.update_layout(template='plotly_dark', height=350)
                        st.plotly_chart(fig_ips, use_container_width=True)
                    else:
                        st.info("No valid foreign addresses found")
        
        st.markdown("---")
        
        # 5. FILE ACCESS PATTERNS
        st.subheader(" File Access Patterns")
        
        if not files_df.empty:
            col_f1, col_f2 = st.columns(2)
            
            with col_f1:
                st.markdown("#### File System Analysis")
                st.metric(" Total File Objects", len(files_df))

                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    files_df['Extension'] = files_df[name_col].astype(str).str.extract(r'\.([^.]+)$')[0]
                    ext_counts = files_df['Extension'].value_counts().head(10)
                        
                                        
                    ext_df = pd.DataFrame({
                        'Extension': ext_counts.index,
                        'Count': ext_counts.values
                    })
                    fig_ext = px.bar(
                        ext_df,
                        x='Extension',
                        y='Count',
                        title='Top 10 File Extensions',
                        color='Count',
                        color_continuous_scale='Greens'
                    )
                    fig_ext.update_layout(template='plotly_dark', height=300)
                    st.plotly_chart(fig_ext, use_container_width=True)
            
            with col_f2:
                st.markdown("#### File Statistics")
                st.metric("Unique Files", len(files_df))
                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    unique_names = files_df[name_col].nunique()
                    st.metric("Unique Names", unique_names)
        
        st.markdown("---")
        
        # # 6. MITRE ATT&CK HEATMAP
        # st.subheader(" MITRE ATT&CK Technique Coverage")
        
        # st.info(" MITRE ATT&CK mapping shows which attack techniques were observed in the snapshot")
        
        # if not procs_df.empty and 'suspicious_score' in procs_df.columns:
        #     suspicious_count = len(procs_df[procs_df['suspicious_score'] > 0])
            
        #     techniques = {
        #         'T1055 - Process Injection': min(suspicious_count * 0.3, 10),
        #         'T1059 - Command Execution': min(suspicious_count * 0.4, 10),
        #         'T1071 - Application Layer Protocol': min(len(conns_df) * 0.1, 10) if not conns_df.empty else 0,
        #         'T1082 - System Information Discovery': min(len(procs_df) * 0.05, 10),
        #         'T1083 - File Discovery': min(len(files_df) * 0.02, 10) if not files_df.empty else 0,
        #         'T1057 - Process Discovery': min(len(procs_df) * 0.08, 10),
        #         'T1049 - System Network Connections': min(len(conns_df) * 0.15, 10) if not conns_df.empty else 0,
        #     }
            
        #     fig_mitre = go.Figure(data=go.Bar(
        #         x=list(techniques.values()),
        #         y=list(techniques.keys()),
        #         orientation='h',
        #         marker=dict(
        #             color=list(techniques.values()),
        #             colorscale='Reds',
        #             showscale=True,
        #             colorbar=dict(title="Confidence")
        #         )
        #     ))
            
        #     fig_mitre.update_layout(
        #         title='MITRE ATT&CK Techniques Detected',
        #         xaxis_title='Confidence Score',
        #         yaxis_title='Technique',
        #         template='plotly_dark',
        #         height=400
        #     )
        #     st.plotly_chart(fig_mitre, use_container_width=True)
        
        # st.markdown("---")
        
        # 7. TOP 10 ANALYTICS
        st.subheader(" Top 10 Analytics")
        
        tab_top1, tab_top2, tab_top3 = st.tabs([" Processes", " Network", " Files"])
        
        with tab_top1:
            if not procs_df.empty:
                col_top1, col_top2 = st.columns(2)
                
                with col_top1:
                    st.markdown("#### Top 10 Most Active Processes")
                    if 'Threads' in procs_df.columns:
                        name_col = 'ImageFileName' if 'ImageFileName' in procs_df.columns else 'comm'
                        pid_col = 'PID' if 'PID' in procs_df.columns else 'pid'
                        top_active = procs_df.nlargest(10, 'Threads')[[name_col, pid_col, 'Threads']].reset_index(drop=True)
                        top_active.index = top_active.index + 1
                        st.dataframe(top_active, use_container_width=True)
                
                with col_top2:
                    st.markdown("#### Top 10 Most Suspicious")
                    if 'suspicious_score' in procs_df.columns:
                        suspicious = procs_df[procs_df['suspicious_score'] > 0]
                        if not suspicious.empty:
                            name_col = 'ImageFileName' if 'ImageFileName' in procs_df.columns else 'comm'
                            pid_col = 'PID' if 'PID' in procs_df.columns else 'pid'
                            top_susp = suspicious.nlargest(10, 'suspicious_score')[[name_col, pid_col, 'suspicious_score']].reset_index(drop=True)
                            top_susp.index = top_susp.index + 1
                            st.dataframe(top_susp, use_container_width=True)
                        else:
                            st.success(" No suspicious processes!")
        
        with tab_top2:
            if not conns_df.empty:
                col_net1, col_net2 = st.columns(2)
                
                with col_net1:
                    st.markdown("#### Top 10 Connected IPs")
                    if 'ForeignAddr' in conns_df.columns:
                        conns_df['ForeignAddr'] = conns_df['ForeignAddr'].fillna('').astype(str)
                        external = conns_df[
                            (conns_df['ForeignAddr'] != '') &
                            (conns_df['ForeignAddr'] != '0.0.0.0') &
                            (conns_df['ForeignAddr'] != '::') &
                            (~conns_df['ForeignAddr'].str.startswith('127.')) &
                            (~conns_df['ForeignAddr'].str.startswith('::1'))
                        ]
                        if not external.empty:
                            top_ips = external['ForeignAddr'].value_counts().head(10).reset_index()
                            top_ips.columns = ['IP Address', 'Count']
                            top_ips.index = top_ips.index + 1
                            st.dataframe(top_ips, use_container_width=True)
                        else:
                            st.info("No external connections")
                
                with col_net2:
                    st.markdown("#### Top 10 Listening Ports")
                    if 'LocalAddr' in conns_df.columns and 'LocalPort' in conns_df.columns:
                        conns_df['LocalAddr'] = conns_df['LocalAddr'].fillna('').astype(str)
                        listening = conns_df[
                            (conns_df['LocalAddr'].isin(['0.0.0.0', '::'])) |
                            (conns_df['LocalAddr'].str.startswith('0.0.0.0')) |
                            (conns_df['LocalAddr'].str.startswith('::'))
                        ]
                        if not listening.empty:
                            top_listening = listening['LocalPort'].value_counts().head(10).reset_index()
                            top_listening.columns = ['Port', 'Count']
                            port_names = {
                                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                                3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
                                3389: 'RDP', 445: 'SMB', 139: 'NetBIOS'
                            }
                            top_listening['Service'] = top_listening['Port'].map(port_names).fillna('Unknown')
                            top_listening.index = top_listening.index + 1
                            st.dataframe(top_listening, use_container_width=True)
                            
                            suspicious_ports = [4444, 31337, 1337, 8080, 8888]
                            susp_found = top_listening[top_listening['Port'].isin(suspicious_ports)]
                            if not susp_found.empty:
                                st.warning(f" Found {len(susp_found)} suspicious ports!")
                        else:
                            st.info("No listening services")
        
        with tab_top3:
            if not files_df.empty:
                col_file1, col_file2 = st.columns(2)
                
                with col_file1:
                    st.markdown("#### Top 10 File Extensions")
                    if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                        name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                        files_df['Extension'] = files_df[name_col].astype(str).str.extract(r'\.([^.]+)$')[0]
                        ext_counts = files_df['Extension'].value_counts().head(10).reset_index()
                        ext_counts.columns = ['Extension', 'Count']
                        ext_counts.index = ext_counts.index + 1
                        st.dataframe(ext_counts, use_container_width=True)
                
                with col_file2:
                    st.markdown("#### Top 10 Accessed Paths")
                    if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                        name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                        files_df['Directory'] = files_df[name_col].astype(str).str.rsplit('\\', n=1).str[0]
                        dir_counts = files_df['Directory'].value_counts().head(10).reset_index()
                        dir_counts.columns = ['Directory', 'Count']
                        dir_counts.index = dir_counts.index + 1
                        dir_counts['Directory'] = dir_counts['Directory'].str[-50:]
                        st.dataframe(dir_counts, use_container_width=True)
        
        st.markdown("---")
        
        # 8. COMPREHENSIVE STATISTICS
        st.subheader(" Comprehensive Statistics")
        
        col_s1, col_s2, col_s3 = st.columns(3)
        
        with col_s1:
            st.markdown("#### Process Stats")
            st.metric("Total Processes", len(procs_df) if not procs_df.empty else 0)
            if not procs_df.empty and 'suspicious_score' in procs_df.columns:
                suspicious = len(procs_df[procs_df['suspicious_score'] > 0])
                st.metric("Suspicious", suspicious)
                st.metric("Clean", len(procs_df) - suspicious)
        
        with col_s2:
            st.markdown("#### Network Stats")
            st.metric("Total Connections", len(conns_df) if not conns_df.empty else 0)
            if not conns_df.empty:
                if 'State' in conns_df.columns:
                    established = len(conns_df[conns_df['State'].str.upper() == 'ESTABLISHED'])
                    st.metric("Established", established)
                if 'ForeignAddr' in conns_df.columns:
                    unique_ips = conns_df['ForeignAddr'].nunique()
                    st.metric("Unique IPs", unique_ips)
        
        with col_s3:
            st.markdown("#### File Stats")
            st.metric("Total Files", len(files_df) if not files_df.empty else 0)
            if not files_df.empty:
                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    unique_files = files_df[name_col].nunique()
                    st.metric("Unique Names", unique_files)
        
        st.markdown("---")
        
        # EXPORT
        st.subheader(" Export Results")
        
        if st.button(" Generate JSON Report", use_container_width=True, type="primary"):
            report = generate_json_report(results)
            st.download_button(
                "Download Report",
                report,
                f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
                use_container_width=True
            )

# TAB 4 - COMPREHENSIVE FORENSICS
# TAB 4 - COMPREHENSIVE FORENSICS
with tab4:
    st.title("🔍 Deep Forensics Analysis")
    
    if not st.session_state.analysis_complete:
        st.info("ℹ️ Complete analysis first to view deep forensics")
    else:
        results = st.session_state.analysis_results
        procs = results.get('processes', [])
        conns = results.get('connections', [])
        files = results.get('file_objects', [])
        
        # Get OS type
        os_type = st.session_state.get('os_type', 'Unknown')
        
        # 4 Analysis sections with radio buttons
        analysis_section = st.radio("Analysis Section:", 
                                    ["🔎 Process Investigation", "🌐 Network Forensics", "📦 System Artifacts", "⚠️ Threat Indicators"],
                                    horizontal=True)
        
        st.markdown("---")
        
        # SECTION 1: PROCESS INVESTIGATION
        if analysis_section == "🔎 Process Investigation":
            st.markdown("### 🔎 Process Investigation")
            
            # Process Statistics (OS-aware)
            total_procs = len(procs)
            
            # Detect system vs user processes based on OS
            if os_type.lower() == "windows":
                system_procs = len([p for p in procs if 'NT AUTHORITY' in str(p.get('User', '')) or 'SYSTEM' in str(p.get('User', ''))])
            elif os_type.lower() in ["linux", "macos"]:
                system_procs = len([p for p in procs if p.get('User') in ['0', 0, 'root', 'Unknown']])
            else:
                system_procs = 0
            
            user_procs = total_procs - system_procs
            terminated = len([p for p in procs if p.get('ExitTime')])
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Processes", total_procs)
            col2.metric("System Processes", system_procs)
            col3.metric("User Processes", user_procs)
            col4.metric("Terminated", terminated)
            
            st.markdown("---")
            
            # Parent-Child Relationships
            st.markdown("#### 👨‍👧‍👦 Parent-Child Process Trees")
            
            # Build parent-child map
            parent_child_map = {}
            for p in procs:
                if isinstance(p, dict):
                    ppid = p.get('PPID') or p.get('ppid')
                    if ppid is not None:
                        if ppid not in parent_child_map:
                            parent_child_map[ppid] = []
                        parent_child_map[ppid].append(p)
            
            col_tree1, col_tree2 = st.columns(2)
            
            with col_tree1:
                st.markdown("**Key Parent Processes**")
                
                # Define key processes per OS
                if os_type.lower() == "windows":
                    key_parents = ['explorer.exe', 'services.exe', 'winlogon.exe', 'wininit.exe']
                elif os_type.lower() == "linux":
                    key_parents = ['systemd', 'init', 'kthreadd']
                elif os_type.lower() == "macos":
                    key_parents = ['launchd', 'kernel_task']
                else:
                    key_parents = []
                
                for parent_name in key_parents:
                    parent_proc = next((p for p in procs if parent_name.lower() in str(p.get('ImageFileName', '') or p.get('comm', '')).lower()), None)
                    if parent_proc:
                        parent_pid = parent_proc.get('PID') or parent_proc.get('pid')
                        children = parent_child_map.get(parent_pid, [])
                        with st.expander(f"📁 {parent_name} (PID: {parent_pid}) - {len(children)} children"):
                            if children:
                                for child in children[:10]:
                                    child_name = child.get('ImageFileName') or child.get('comm', 'Unknown')
                                    child_pid = child.get('PID') or child.get('pid')
                                    st.write(f"  └─ {child_name} (PID: {child_pid})")
                            else:
                                st.info("No child processes")
            
            with col_tree2:
                st.markdown("**Suspicious Process Trees**")
                
                # Define suspicious processes per OS
                if os_type.lower() == "windows":
                    suspicious_parents = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
                elif os_type.lower() == "linux":
                    suspicious_parents = ['bash', 'sh', 'nc', 'netcat']
                elif os_type.lower() == "macos":
                    suspicious_parents = ['bash', 'sh', 'osascript', 'python']
                else:
                    suspicious_parents = []
                
                for parent_name in suspicious_parents:
                    parent_procs = [p for p in procs if parent_name.lower() in str(p.get('ImageFileName', '') or p.get('comm', '')).lower()]
                    for parent_proc in parent_procs[:5]:
                        parent_pid = parent_proc.get('PID') or parent_proc.get('pid')
                        children = parent_child_map.get(parent_pid, [])
                        if children:
                            with st.expander(f"⚠️ {parent_name} (PID: {parent_pid}) - {len(children)} children", expanded=False):
                                for child in children[:10]:
                                    child_name = child.get('ImageFileName') or child.get('comm', 'Unknown')
                                    child_pid = child.get('PID') or child.get('pid')
                                    st.write(f"  └─ {child_name} (PID: {child_pid})")
            
            st.markdown("---")
            
            # Short-lived processes
            st.markdown("#### ⏱️ Short-Lived Processes")
            short_lived = [p for p in procs if p.get('ExitTime')]
            
            if short_lived:
                short_df = pd.DataFrame([{
                    'Process': p.get('ImageFileName') or p.get('comm', 'Unknown'),
                    'PID': p.get('PID') or p.get('pid'),
                    'PPID': p.get('PPID') or p.get('ppid'),
                    'Start Time': p.get('CreateTime', 'N/A'),
                    'Exit Time': p.get('ExitTime', 'N/A'),
                    'Suspicion Score': p.get('suspicious_score', 0)
                } for p in short_lived[:20]])
                st.dataframe(short_df, height=300)
                st.download_button("💾 Download CSV", short_df.to_csv(index=False), "short_lived_processes.csv")
            else:
                st.info("ℹ️ No terminated processes detected")
            
            st.markdown("---")
            
            # Process Lookup
            st.markdown("#### 🔍 Process Lookup")
            search_term = st.text_input("Search by process name or PID:")
            
            if search_term:
                matches = [p for p in procs if 
                          search_term.lower() in str(p.get('ImageFileName', '') or p.get('comm', '')).lower() or
                          search_term in str(p.get('PID') or p.get('pid', ''))]
                
                if matches:
                    st.success(f"✅ Found {len(matches)} matches")
                    for match in matches[:10]:
                        proc_name = match.get('ImageFileName') or match.get('comm', 'Unknown')
                        proc_pid = match.get('PID') or match.get('pid')
                        with st.expander(f"📋 {proc_name} (PID: {proc_pid})"):
                            col_a, col_b, col_c = st.columns(3)
                            col_a.write(f"**PID:** {proc_pid}")
                            col_b.write(f"**PPID:** {match.get('PPID') or match.get('ppid')}")
                            col_c.write(f"**Threads:** {match.get('Threads', match.get('threads', 'N/A'))}")
                            st.write(f"**Path:** {match.get('ImagePath', match.get('path', 'N/A'))}")
                            st.write(f"**User:** {match.get('User', match.get('user', match.get('uid', 'N/A')))}")
                            st.write(f"**Created:** {match.get('CreateTime', 'N/A')}")
                            if match.get('suspicious_score', 0) > 0:
                                st.warning(f"⚠️ Suspicion Score: {match.get('suspicious_score')}")
                else:
                    st.warning("⚠️ No matches found")
        
        # SECTION 2: NETWORK FORENSICS
        elif analysis_section == "🌐 Network Forensics":
            st.markdown("### 🌐 Network Forensics")
            
            # Connection Statistics
            total_conns = len(conns)
            
            # Count connection states
            established = len([c for c in conns if str(c.get('State', '')).upper() == 'ESTABLISHED'])
            listening = len([c for c in conns if str(c.get('State', '')).upper() in ['LISTENING', 'LISTEN']])
            closed = len([c for c in conns if str(c.get('State', '')).upper() in ['CLOSED', 'CLOSE_WAIT', 'TIME_WAIT']])
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Connections", total_conns)
            col2.metric("Established", established)
            col3.metric("Listening", listening)
            col4.metric("Closed", closed)
            
            st.markdown("---")
            
            # Connection State Distribution
            st.markdown("#### 📊 Connection State Distribution")
            if conns:
                state_counts = {}
                for c in conns:
                    state = c.get('State', 'UNKNOWN')
                    if not state or state == '':
                        state = 'UNKNOWN'
                    state_counts[state] = state_counts.get(state, 0) + 1
                
                col_chart, col_table = st.columns(2)
                
                with col_chart:
                    if len(state_counts) > 0:
                        fig = px.pie(
                            names=list(state_counts.keys()),
                            values=list(state_counts.values()),
                            title='Connection States',
                            hole=0.4
                        )
                        fig.update_layout(template='plotly_dark', height=400)
                        st.plotly_chart(fig, use_container_width=True)
                
                with col_table:
                    state_df = pd.DataFrame(list(state_counts.items()), columns=['State', 'Count'])
                    st.dataframe(state_df, height=400)
            
            st.markdown("---")
            
            # IP Address Analysis
            st.markdown("#### 🌍 IP Address Analysis")
            
            ip_tabs = st.tabs(["External IPs", "Private IPs", "Suspicious Ports"])
            
            with ip_tabs[0]:
                st.markdown("**Top External IPs**")
                external_ips = {}
                for c in conns:
                    foreign = str(c.get('ForeignAddr', ''))
                    if foreign and foreign not in ['0.0.0.0', '::', '', 'None']:
                        # Remove port if present
                        ip = foreign.split(':')[0] if ':' in foreign else foreign
                        # Filter out private IPs
                        if not any(ip.startswith(prefix) for prefix in ['10.', '192.168.', '127.', '172.', 'fe80', 'fd', 'fc']):
                            external_ips[ip] = external_ips.get(ip, 0) + 1
                
                if external_ips:
                    sorted_ips = sorted(external_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                    ip_df = pd.DataFrame(sorted_ips, columns=['IP Address', 'Connections'])
                    
                    fig = px.bar(ip_df, x='IP Address', y='Connections', title='Top 10 External IPs')
                    fig.update_layout(template='plotly_dark', height=400)
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.dataframe(ip_df, height=300)
                else:
                    st.info("ℹ️ No external connections found")
            
            with ip_tabs[1]:
                st.markdown("**Private Network Connections**")
                private_conns = []
                for c in conns:
                    foreign = str(c.get('ForeignAddr', ''))
                    if foreign:
                        ip = foreign.split(':')[0] if ':' in foreign else foreign
                        if any(ip.startswith(prefix) for prefix in ['10.', '192.168.']) or any(ip.startswith(f'172.{i}.') for i in range(16, 32)):
                            private_conns.append({
                                'Local': c.get('LocalAddr'),
                                'Remote': foreign,
                                'State': c.get('State'),
                                'Process': c.get('Owner', 'Unknown'),
                                'PID': c.get('PID')
                            })
                
                if private_conns:
                    st.warning(f"⚠️ Found {len(private_conns)} private network connections")
                    st.dataframe(pd.DataFrame(private_conns[:50]), height=300)
                else:
                    st.success("✅ No private network connections detected")
            
            with ip_tabs[2]:
                st.markdown("**Suspicious Port Detection**")
                
                known_malware_ports = {
                    '4444': 'Metasploit Default',
                    '8080': 'HTTP Proxy / Exploit Server',
                    '31337': 'Back Orifice',
                    '1337': 'LEET',
                    '6667': 'IRC',
                    '12345': 'NetBus'
                }
                
                suspicious = []
                for c in conns:
                    local_port = str(c.get('LocalPort', ''))
                    foreign_port = str(c.get('ForeignPort', ''))
                    
                    if local_port in known_malware_ports or foreign_port in known_malware_ports:
                        port = local_port if local_port in known_malware_ports else foreign_port
                        suspicious.append({
                            'Port': port,
                            'Type': known_malware_ports.get(port, 'Unknown'),
                            'Local': c.get('LocalAddr'),
                            'Remote': c.get('ForeignAddr'),
                            'Process': c.get('Owner', 'Unknown'),
                            'PID': c.get('PID'),
                            'State': c.get('State')
                        })
                
                if suspicious:
                    st.error(f"🚨 Found {len(suspicious)} suspicious ports")
                    st.dataframe(pd.DataFrame(suspicious), height=300)
                else:
                    st.success("✅ No suspicious ports detected")
            
            st.markdown("---")
            
            # Process Network Activity
            st.markdown("#### 📡 Process Network Activity")
            process_conns = {}
            for c in conns:
                owner = c.get('Owner', 'Unknown')
                if owner not in process_conns:
                    process_conns[owner] = {
                        'Total': 0,
                        'Established': 0,
                        'Listening': 0,
                        'IPs': set()
                    }
                process_conns[owner]['Total'] += 1
                if str(c.get('State', '')).upper() == 'ESTABLISHED':
                    process_conns[owner]['Established'] += 1
                if str(c.get('State', '')).upper() in ['LISTENING', 'LISTEN']:
                    process_conns[owner]['Listening'] += 1
                foreign = c.get('ForeignAddr', '')
                if foreign and foreign not in ['0.0.0.0', '::']:
                    ip = foreign.split(':')[0] if ':' in foreign else foreign
                    process_conns[owner]['IPs'].add(ip)
            
            proc_net_df = pd.DataFrame([
                {
                    'Process': proc,
                    'Total Connections': data['Total'],
                    'Established': data['Established'],
                    'Listening': data['Listening'],
                    'Unique IPs': len(data['IPs'])
                }
                for proc, data in process_conns.items()
            ]).sort_values('Total Connections', ascending=False)
            
            st.dataframe(proc_net_df, height=400)
            st.download_button("💾 Download CSV", proc_net_df.to_csv(index=False), "process_network_activity.csv")
        
        # SECTION 3: SYSTEM ARTIFACTS
        elif analysis_section == "📦 System Artifacts":
            st.markdown("### 📦 System Artifacts")
            
            # System Configuration
            st.markdown("#### ⚙️ System Configuration")
            metadata = st.session_state.snapshot_info or {}
            
            col_sys1, col_sys2 = st.columns(2)
            
            with col_sys1:
                st.markdown("**Device Information**")
                st.write(f"🖥️ **Computer Name:** {metadata.get('computer_name', 'N/A')}")
                st.write(f"👤 **Username:** {metadata.get('username', 'N/A')}")
                st.write(f"💻 **OS Version:** {metadata.get('os_version', 'N/A')}")
            
            with col_sys2:
                st.markdown("**Snapshot Details**")
                st.write(f"📦 **File Size:** {metadata.get('size_gb', 'N/A')} GB")
                st.write(f"📅 **Analysis Date:** {metadata.get('analysis_time', 'N/A')}")
                st.write(f"🖥️ **OS Type:** {metadata.get('os_type', 'N/A')}")
            
            st.markdown("---")
            
            # Process Timeline
            st.markdown("#### ⏱️ Process Creation Timeline")
            timeline = sorted([p for p in procs if p.get('CreateTime')], key=lambda x: x.get('CreateTime', ''))[:30]
            
            if timeline:
                timeline_df = pd.DataFrame([{
                    'Time': p.get('CreateTime'),
                    'Process': p.get('ImageFileName') or p.get('comm', 'Unknown'),
                    'PID': p.get('PID') or p.get('pid'),
                    'PPID': p.get('PPID') or p.get('ppid'),
                    'User': p.get('User', 'N/A')
                } for p in timeline])
                st.dataframe(timeline_df, height=400)
            else:
                st.info("ℹ️ Timeline data not available")
            
            st.markdown("---")
            
            # File System Activity
            st.markdown("#### 📁 File System Activity")
            
            exe_files = len([f for f in files if str(f.get('FileName', '') or f.get('Name', '')).lower().endswith('.exe')])
            dll_files = len([f for f in files if str(f.get('FileName', '') or f.get('Name', '')).lower().endswith('.dll')])
            other_files = len(files) - exe_files - dll_files
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Files", len(files))
            col2.metric("Executable Files", exe_files)
            col3.metric("DLL Files", dll_files)
            col4.metric("Other Files", other_files)
            
            if files:
                file_sample = pd.DataFrame([{
                    'File Name': f.get('FileName') or f.get('Name') or f.get('path', 'Unknown'),
                    'Offset': f.get('Offset', f.get('offset', f.get('inode', 'N/A'))),
                    'Process': f.get('Process', 'N/A')
                } for f in files[:50]])
                st.dataframe(file_sample, height=300)
            else:
                st.info("ℹ️ No file objects extracted")
        
        # SECTION 4: THREAT INDICATORS
        elif analysis_section == "⚠️ Threat Indicators":
            st.markdown("### ⚠️ Threat Indicators")
            
            # Threat Summary
            high_risk = len([p for p in procs if p.get('suspicious_score', 0) >= 7])
            medium_risk = len([p for p in procs if 4 <= p.get('suspicious_score', 0) < 7])
            low_risk = len([p for p in procs if 1 <= p.get('suspicious_score', 0) < 4])
            
            col1, col2, col3 = st.columns(3)
            col1.metric("🔴 High Risk", high_risk, delta="Critical" if high_risk > 0 else None)
            col2.metric("🟡 Medium Risk", medium_risk, delta="Warning" if medium_risk > 0 else None)
            col3.metric("🟢 Low Risk", low_risk)
            
            st.markdown("---")
            
            # Indicators of Compromise
            st.markdown("#### 🚨 Indicators of Compromise (IOCs)")
            
            ioc_tabs = st.tabs(["Suspicious Processes", "Network IOCs", "Memory Indicators"])
            
            with ioc_tabs[0]:
                st.markdown("**Suspicious Processes**")
                suspicious_procs = [p for p in procs if p.get('suspicious_score', 0) >= 5]
                
                if suspicious_procs:
                    for proc in suspicious_procs[:10]:
                        severity = "🔴 CRITICAL" if proc.get('suspicious_score', 0) >= 7 else "🟡 WARNING"
                        proc_name = proc.get('ImageFileName') or proc.get('comm', 'Unknown')
                        proc_pid = proc.get('PID') or proc.get('pid')
                        
                        with st.expander(f"{severity} - {proc_name} (PID: {proc_pid})"):
                            st.write(f"**Suspicion Score:** {proc.get('suspicious_score')}/10")
                            st.write(f"**Parent PID:** {proc.get('PPID') or proc.get('ppid')}")
                            st.write(f"**User:** {proc.get('User', proc.get('user', proc.get('uid', 'N/A')))}")
                            st.write(f"**Path:** {proc.get('ImagePath', proc.get('path', 'N/A'))}")
                            
                            # Check for children
                            children = [p for p in procs if (p.get('PPID') or p.get('ppid')) == proc_pid]
                            if children:
                                st.warning(f"⚠️ Has {len(children)} child processes")
                                for child in children[:5]:
                                    child_name = child.get('ImageFileName') or child.get('comm', 'Unknown')
                                    child_pid = child.get('PID') or child.get('pid')
                                    st.write(f"  └─ {child_name} (PID: {child_pid})")
                else:
                    st.success("✅ No highly suspicious processes detected")
            
            with ioc_tabs[1]:
                st.markdown("**Network-based IOCs**")
                known_malware_ports = {'4444', '8080', '31337', '1337', '6667', '12345'}
                
                network_iocs = []
                for c in conns:
                    foreign = str(c.get('ForeignAddr', ''))
                    local_port = str(c.get('LocalPort', ''))
                    foreign_port = str(c.get('ForeignPort', ''))
                    
                    if local_port in known_malware_ports or foreign_port in known_malware_ports:
                        port = local_port if local_port in known_malware_ports else foreign_port
                        ip = foreign.split(':')[0] if ':' in foreign else foreign
                        network_iocs.append({
                            'IP': ip,
                            'Port': port,
                            'Process': c.get('Owner'),
                            'State': c.get('State'),
                            'Indicator': 'Known malware port'
                        })
                
                if network_iocs:
                    st.error(f"🚨 Found {len(network_iocs)} network IOCs")
                    st.dataframe(pd.DataFrame(network_iocs), height=300)
                else:
                    st.success("✅ No network IOCs detected")
            
            with ioc_tabs[2]:
                st.markdown("**Memory-based Indicators**")
                
                # Check for shell processes (OS-aware)
                if os_type.lower() == "windows":
                    shell_keywords = ['powershell', 'cmd', 'wscript', 'cscript']
                else:  # Linux/macOS
                    shell_keywords = ['bash', 'sh', 'zsh', 'python', 'perl', 'ruby']
                
                shell_procs = [p for p in procs if any(keyword in str(p.get('ImageFileName', '') or p.get('comm', '')).lower() for keyword in shell_keywords)]
                
                if shell_procs:
                    st.warning(f"⚠️ Detected {len(shell_procs)} potential injection vectors:")
                    for p in shell_procs[:10]:
                        proc_name = p.get('ImageFileName') or p.get('comm', 'Unknown')
                        proc_pid = p.get('PID') or p.get('pid')
                        st.write(f"  - {proc_name} (PID: {proc_pid})")
                else:
                    st.success("✅ No obvious memory indicators detected")

# SIDEBAR
with st.sidebar:
    st.markdown("### VAST v3.0")
    st.markdown("**Advanced Forensics Platform**")
    st.markdown("---")
    
    if st.session_state.analysis_complete and st.session_state.snapshot_info:
        st.markdown("### Snapshot Info")
        info = st.session_state.snapshot_info
        st.markdown(f"**User:** {info.get('username', 'Unknown')}")
        st.markdown(f"**Device:** {info.get('computer_name', 'Unknown')}")
        st.markdown(f"**OS:** {info.get('os_version', 'Unknown')}")
        st.markdown(f"**Size:** {info.get('size_gb', 'N/A')} GB")
        st.markdown("---")
    
    st.markdown("### Dashboard")
    st.markdown("""
    **Tab 1:** Upload & Configure
    
    **Tab 2:** Timeline & Analysis
    
    **Tab 3:** Advanced Analytics
    
    **Tab 4:** Deep Forensics
    """)
    
    st.markdown("---")
    st.markdown("### Features")
    st.markdown("""
    - 100GB file support
    - macOS, Linux, Windows
    - Device identification
    - AI threat detection
    - MITRE ATT&CK
    - 8 visualizations
    - Real-time search
    """)
    
    st.markdown("---")
    st.markdown("**ICT3215 - Group 16**")
    st.markdown("Singapore Institute of Technology")
    
    if st.session_state.analysis_complete:
        st.success(" Analysis Complete")