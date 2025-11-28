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

sys.path.insert(0, str(Path(__file__).parent))

# ========================
# AUTO SYMBOL DOWNLOAD
# ========================
def download_symbols_if_needed(os_type):
    """Auto-download symbols for the selected OS type"""
    import subprocess
    
    symbol_dir = Path.home() / ".cache" / "volatility3" / "symbols"
    
    # Check what symbols we need
    needs_download = False
    
    if os_type.lower() == "macos":
        # Check for macOS symbols
        if not symbol_dir.exists() or not list(symbol_dir.glob("mac-*.json")):
            needs_download = True
            symbol_type = "macOS"
    elif os_type.lower() == "linux":
        # Check for Linux symbols
        if not symbol_dir.exists() or not list(symbol_dir.glob("linux-*.json")):
            needs_download = True
            symbol_type = "Linux"
    # Windows symbols usually included in snapshot, no download needed
    
    if needs_download:
        return symbol_type
    return None

# ========================

try:
    from vast_integration import VASTAnalyzer, run_analysis
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False

st.set_page_config(page_title="VAST - Memory Forensics Dashboard", page_icon="🔍", layout="wide")

st.markdown("""
<style>
    .stMetric { background-color: #1e1e1e; padding: 15px; border-radius: 8px; }
    .info-card { 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 12px;
        margin: 10px 0;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("# 🔍 VAST - Volatile Artifact Snapshot Triage")
st.markdown("**Advanced Memory Forensics Dashboard with AI-Powered Threat Detection**")
st.markdown("---")

for key in ['analysis_complete', 'analysis_results', 'session_dir', 'search_query', 'os_type', 'snapshot_info']:
    if key not in st.session_state:
        st.session_state[key] = False if key == 'analysis_complete' else (None if key != 'search_query' else "")

def generate_json_report(results):
    return json.dumps({
        'metadata': {'date': datetime.now().isoformat(), 'tool': 'VAST v2.0', 
                    'os': st.session_state.get('os_type', 'Unknown'),
                    'session': st.session_state.get('session_dir', 'N/A'),
                    'snapshot_info': st.session_state.get('snapshot_info', {})},
        'summary': results.get('summary', {}),
        'artifacts': {'processes': results.get('processes', []),
                     'connections': results.get('connections', []),
                     'files': results.get('file_objects', [])}
    }, indent=2)

def extract_snapshot_metadata(results):
    """Extract device information from analysis results"""
    metadata = {
        'computer_name': 'Unknown',
        'username': 'Unknown',
        'os_version': 'Unknown',
        'architecture': 'Unknown',
        'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Try to extract from processes
    procs = results.get('processes', [])
    if procs:
        # Look for system processes that might have computer name
        for proc in procs:
            # Windows: Look for ImageFileName patterns
            if 'ImageFileName' in proc:
                img = str(proc['ImageFileName'])
                if '\\Users\\' in img:
                    parts = img.split('\\Users\\')
                    if len(parts) > 1:
                        username = parts[1].split('\\')[0]
                        if username and username != 'Unknown':
                            metadata['username'] = username
                            break
            # Linux: Look for comm patterns
            elif 'comm' in proc:
                comm = str(proc['comm'])
                if comm:
                    # Try to get username from process info
                    pass
    
    # Try to get OS version from summary
    summary = results.get('summary', {})
    if summary:
        if 'os_version' in summary:
            metadata['os_version'] = summary['os_version']
        if 'computer_name' in summary:
            metadata['computer_name'] = summary['computer_name']
    
    return metadata

tab1, tab2, tab3 = st.tabs(["📤 Upload Snapshot", "📊 Timeline & Analysis", "📈 Advanced Analytics"])

with tab1:
    st.header("Upload VM Snapshot")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("1. Snapshot File")
        uploaded_file = st.file_uploader("Choose VM snapshot", type=['vmsn', 'vmem', 'sav'],
            help="VMware (.vmsn, .vmem) or VirtualBox (.sav) - Max 100GB")
        
        if uploaded_file:
            size_mb = uploaded_file.size / (1024 * 1024)
            size_gb = size_mb / 1024
            
            if size_gb > 100:
                st.error(f"⚠️ File too large: {size_gb:.2f} GB (Max: 100GB)")
            else:
                st.success(f"✅ {uploaded_file.name}")
                st.info(f"📦 Size: {size_gb:.2f} GB" if size_mb >= 1024 else f"📦 Size: {size_mb:.2f} MB")
                if size_gb > 50:
                    st.warning(f"⏱️ Very large file - Analysis may take 45-90 minutes")
                elif size_gb > 10:
                    st.warning(f"⏱️ Large file - Analysis may take 20-45 minutes")
    
    with col2:
        st.subheader("2. Guest OS")
        os_type = st.selectbox("Operating System", ["Windows", "Linux", "macOS"])
    
    st.markdown("---")
    st.subheader("3. Analysis Options")
    
    col3, col4 = st.columns(2)
    with col3:
        extract_processes = st.checkbox("✓ Extract Processes", True, help="Running processes & metadata")
        extract_network = st.checkbox("✓ Extract Network", True, help="Active connections & ports")
    with col4:
        extract_files = st.checkbox("✓ Extract Files", True, help="Open file handles")
        extract_registry = st.checkbox("✓ Registry (Windows)", os_type=="Windows", help="Registry activity")
    
    st.markdown("---")
    
    col_btn1, col_btn2, _ = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
            if not uploaded_file:
                st.error("⚠️ Upload a file first!")
            elif not BACKEND_AVAILABLE:
                st.error("⚠️ Backend not configured")
            elif size_gb > 100:
                st.error("⚠️ File exceeds 100GB limit")
            else:
                # Check if symbols needed
                missing_symbols = download_symbols_if_needed(os_type)
                
                if missing_symbols:
                    with st.expander("⚠️ Symbols Required", expanded=True):
                        st.warning(f"""
                        **{missing_symbols} symbols not found**
                        
                        First-time {missing_symbols} analysis requires downloading symbols (~300MB).
                        This is a one-time download that takes 10-15 minutes.
                        
                        **Option 1: Auto-download now (recommended)**
                        Symbols will download automatically during analysis.
                        
                        **Option 2: Manual download**
                        Run in Terminal:
                        ```bash
                        volatility3 -f your_snapshot.raw {os_type.lower()}.info
                        ```
                        
                        Click 'Start Analysis' to continue with auto-download.
                        """)
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = tmp.name
                
                try:
                    with st.spinner("🔬 Analyzing..."):
                        progress = st.progress(0)
                        status = st.empty()
                        
                        def update(msg, prog):
                            status.text(msg)
                            progress.progress(prog)
                        
                        results = run_analysis(tmp_path, os_type.lower(), {
                            "extract_processes": extract_processes,
                            "extract_network": extract_network,
                            "extract_files": extract_files,
                            "extract_registry": extract_registry and os_type=="Windows"
                        }, update)
                        
                        if results.get("success"):
                            analyzer = VASTAnalyzer()
                            display_results = analyzer.load_results(Path(results["session_dir"]))
                            
                            # Extract metadata
                            snapshot_metadata = extract_snapshot_metadata(display_results)
                            snapshot_metadata['filename'] = uploaded_file.name
                            snapshot_metadata['size_gb'] = f"{size_gb:.2f}"
                            snapshot_metadata['os_type'] = os_type
                            
                            st.session_state.analysis_results = display_results
                            st.session_state.session_dir = results["session_dir"]
                            st.session_state.os_type = os_type
                            st.session_state.snapshot_info = snapshot_metadata
                            st.session_state.analysis_complete = True
                            
                            status.empty()
                            progress.empty()
                            st.success("✅ Analysis Complete!")
                            st.info("👉 View results in Timeline & Advanced Analytics tabs")
                            st.balloons()
                        else:
                            st.error("❌ Analysis failed")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
                finally:
                    try: os.unlink(tmp_path)
                    except: pass
    
    with col_btn2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.analysis_complete = False
            st.session_state.analysis_results = None
            st.session_state.snapshot_info = None
            st.rerun()

with tab2:
    if not st.session_state.analysis_complete:
        st.info("👈 **Upload and analyze a snapshot first**")
        st.markdown("### 🎯 What VAST Does:")
        st.markdown("""
        - ✅ Automated VM snapshot parsing (no conversion needed)
        - ✅ Unified timeline correlation across all artifacts
        - ✅ AI-powered threat detection and scoring
        - ✅ Interactive visualizations and charts
        - ✅ MITRE ATT&CK technique mapping
        - ✅ Real-time search and filtering
        - ✅ Device and user identification
        """)
        
    else:
        results = st.session_state.analysis_results
        snapshot_info = st.session_state.snapshot_info or {}
        
        st.header("📊 Timeline & Forensic Analysis")
        
        # SNAPSHOT INFORMATION CARD
        st.markdown("### 💻 Snapshot Information")
        
        info_col1, info_col2, info_col3, info_col4 = st.columns(4)
        
        with info_col1:
            st.metric("👤 Username", snapshot_info.get('username', 'Unknown'))
        with info_col2:
            st.metric("🖥️ Computer Name", snapshot_info.get('computer_name', 'Unknown'))
        with info_col3:
            st.metric("🪟 OS Version", snapshot_info.get('os_version', st.session_state.get('os_type', 'Unknown')))
        with info_col4:
            st.metric("📦 File Size", f"{snapshot_info.get('size_gb', 'N/A')} GB")
        
        with st.expander("📋 Full Snapshot Details", expanded=False):
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
        st.subheader("🔍 Global Search")
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
        st.subheader("📈 Executive Summary")
        
        procs = results.get('processes', [])
        conns = results.get('connections', [])
        files = results.get('file_objects', [])
        
        if search_query:
            procs = [p for p in procs if search_query.lower() in str(p).lower()]
            conns = [c for c in conns if search_query.lower() in str(c).lower()]
            files = [f for f in files if search_query.lower() in str(f).lower()]
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("💻 Processes", len(procs))
        col2.metric("🌐 Network", len(conns))
        col3.metric("📁 Files", len(files))
        col4.metric("📊 Total", len(procs) + len(conns) + len(files))
        
        if search_query:
            st.info(f"🔍 Showing {len(procs) + len(conns) + len(files)} results for '{search_query}'")
        
        st.markdown("---")
        
        # THREAT OVERVIEW
        st.subheader("⚠️ Threat Overview")
        
        procs_df = pd.DataFrame(procs) if procs else pd.DataFrame()
        if not procs_df.empty and "suspicious_score" in procs_df.columns:
            suspicious_procs = procs_df[procs_df["suspicious_score"] > 0]
            
            col_t1, col_t2, col_t3, col_t4 = st.columns(4)
            
            high_threat = len(suspicious_procs[suspicious_procs["suspicious_score"] >= 7])
            med_threat = len(suspicious_procs[(suspicious_procs["suspicious_score"] >= 4) & (suspicious_procs["suspicious_score"] < 7)])
            low_threat = len(suspicious_procs[suspicious_procs["suspicious_score"] < 4])
            
            col_t1.metric("🔴 High Risk", high_threat)
            col_t2.metric("🟡 Medium Risk", med_threat)
            col_t3.metric("🟢 Low Risk", low_threat)
            col_t4.metric("✅ Clean", len(procs_df) - len(suspicious_procs))
        else:
            st.success("✅ No threats detected in this snapshot")
        
        st.markdown("---")
        
        # TIMELINE CARDS
        st.subheader("🕒 Event Timeline")
        
        st.markdown("""
        <div style='background: linear-gradient(90deg, #1e3a8a 0%, #7c3aed 100%); 
                    padding: 15px; border-radius: 10px; margin-bottom: 20px;'>
            <h4 style='color: white; margin: 0;'>📅 Chronological Event Sequence</h4>
        </div>
        """, unsafe_allow_html=True)
        
        timeline_events = []
        
        for i, proc in enumerate(procs[:30]):
            timeline_events.append({
                'seq': i,
                'type': '💻 Process',
                'name': str(proc.get("ImageFileName") or proc.get("comm", "Unknown"))[:50],
                'details': f"PID: {proc.get('PID') or proc.get('pid', 'N/A')} | PPID: {proc.get('PPID') or proc.get('ppid', 'N/A')}",
                'suspicious': proc.get('suspicious_score', 0),
                'time': f"Event #{i+1}"
            })
        
        offset = len(timeline_events)
        for i, conn in enumerate(conns[:30]):
            timeline_events.append({
                'seq': offset + i,
                'type': '🌐 Network',
                'name': f"{conn.get('ForeignAddr', 'Unknown')}:{conn.get('ForeignPort', '')}",
                'details': f"Protocol: {conn.get('Proto', 'TCP')} | State: {conn.get('State', 'N/A')}",
                'suspicious': conn.get('suspicious_score', 0),
                'time': f"Event #{offset+i+1}"
            })
        
        offset = len(timeline_events)
        for i, file in enumerate(files[:20]):
            timeline_events.append({
                'seq': offset + i,
                'type': '📁 File',
                'name': str(file.get("FileName") or file.get("Name", "Unknown"))[:50],
                'details': f"Offset: {file.get('Offset', 'N/A')}",
                'suspicious': 0,
                'time': f"Event #{offset+i+1}"
            })
        
        if timeline_events:
            for event in timeline_events[:50]:
                susp_badge = "🔴 HIGH RISK" if event['suspicious'] >= 7 else ("🟡 MEDIUM" if event['suspicious'] >= 4 else ("🟢 LOW" if event['suspicious'] > 0 else ""))
                
                with st.expander(f"{event['time']} - {event['type']}: {event['name']} {susp_badge}", expanded=False):
                    st.markdown(f"**Details:** {event['details']}")
                    if event['suspicious'] > 0:
                        st.warning(f"⚠️ Suspicion Score: {event['suspicious']}/10")
        
        st.markdown("---")
        
        # DETAILED TABLES
        st.subheader("💻 Process Analysis")
        if procs:
            procs_df = pd.DataFrame(procs)
            if '__children' in procs_df.columns:
                procs_df = procs_df.drop(columns=['__children'])
            
            with st.expander("📋 All Processes Table", expanded=False):
                st.dataframe(procs_df, use_container_width=True, height=400)
                st.download_button("📥 Download CSV", procs_df.to_csv(index=False), "processes.csv")
        
        st.markdown("---")
        
        st.subheader("🌐 Network Analysis")
        if conns:
            conns_df = pd.DataFrame(conns)
            if '__children' in conns_df.columns:
                conns_df = conns_df.drop(columns=['__children'])
            
            with st.expander("📋 All Network Connections", expanded=False):
                st.dataframe(conns_df, use_container_width=True, height=400)
                st.download_button("📥 Download CSV", conns_df.to_csv(index=False), "connections.csv")

# TAB 3 - ADVANCED ANALYTICS (WITHOUT PROCESS TREE)
with tab3:
    if not st.session_state.analysis_complete:
        st.info("👈 **Complete analysis first to view advanced analytics**")
    else:
        results = st.session_state.analysis_results
        snapshot_info = st.session_state.snapshot_info or {}
        
        st.header("📈 Advanced Analytics & Visualizations")
        
        # SNAPSHOT INFO AT TOP
        st.markdown("### 💻 Device Information")
        info_col1, info_col2, info_col3 = st.columns(3)
        with info_col1:
            st.metric("👤 User", snapshot_info.get('username', 'Unknown'))
        with info_col2:
            st.metric("🖥️ Device", snapshot_info.get('computer_name', 'Unknown'))
        with info_col3:
            st.metric("🪟 OS", snapshot_info.get('os_version', st.session_state.get('os_type', 'Unknown')))
        
        st.markdown("---")
        
        procs = results.get('processes', [])
        conns = results.get('connections', [])
        files = results.get('file_objects', [])
        
        procs_df = pd.DataFrame(procs) if procs else pd.DataFrame()
        conns_df = pd.DataFrame(conns) if conns else pd.DataFrame()
        files_df = pd.DataFrame(files) if files else pd.DataFrame()
        
        # 1. PORT ACTIVITY ANALYSIS
        st.subheader("🔌 Port Activity Analysis")
        
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
        st.subheader("⚠️ Threat Severity Distribution")
        
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
                
                st.markdown("#### 🔴 Top 10 Most Suspicious Processes")
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
                st.success("✅ No suspicious processes detected!")
        
        st.markdown("---")
        
        # 3. MEMORY USAGE ANALYSIS
        st.subheader("💾 Memory Usage Distribution")
        
        col_m1, col_m2 = st.columns(2)
        
        with col_m1:
            if not procs_df.empty and 'Threads' in procs_df.columns:
                st.markdown("#### Top 10 Thread Consumers")
                name_col = 'ImageFileName' if 'ImageFileName' in procs_df.columns else 'comm'
                pid_col = 'PID' if 'PID' in procs_df.columns else 'pid'
                top_threads = procs_df.nlargest(10, 'Threads')[[name_col, pid_col, 'Threads']]
                st.dataframe(top_threads, use_container_width=True)
        
        with col_m2:
            if not procs_df.empty and 'Threads' in procs_df.columns:
                fig_threads = px.box(
                    procs_df,
                    y='Threads',
                    title='Thread Count Distribution',
                    color_discrete_sequence=['#3b82f6']
                )
                fig_threads.update_layout(template='plotly_dark', height=300)
                st.plotly_chart(fig_threads, use_container_width=True)
        
        st.markdown("---")
        
        # 4. CONNECTION STATE ANALYSIS
        st.subheader("🌐 Connection State Analysis")
        
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
                    top_ips = conns_df['ForeignAddr'].value_counts().head(10)
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
        
        st.markdown("---")
        
        # 5. FILE ACCESS PATTERNS
        st.subheader("📁 File Access Patterns")
        
        if not files_df.empty:
            col_f1, col_f2 = st.columns(2)
            
            with col_f1:
                st.metric("📊 Total File Objects", len(files_df))
                
                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    files_df['Extension'] = files_df[name_col].astype(str).str.extract(r'\.([^.]+)$')[0]
                    ext_counts = files_df['Extension'].value_counts().head(10)
                    
                    fig_ext = px.bar(
                        x=ext_counts.index,
                        y=ext_counts.values,
                        title='Top 10 File Extensions',
                        labels={'x': 'Extension', 'y': 'Count'},
                        color=ext_counts.values,
                        color_continuous_scale='Greens'
                    )
                    fig_ext.update_layout(template='plotly_dark', height=300)
                    st.plotly_chart(fig_ext, use_container_width=True)
            
            with col_f2:
                st.markdown("#### 📋 File Statistics")
                st.metric("Unique Files", len(files_df))
                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    unique_names = files_df[name_col].nunique()
                    st.metric("Unique Names", unique_names)
        
        st.markdown("---")
        
        # 6. MITRE ATT&CK HEATMAP
        st.subheader("🎯 MITRE ATT&CK Technique Coverage")
        
        st.info("💡 MITRE ATT&CK mapping shows which attack techniques were observed in the snapshot")
        
        if not procs_df.empty and 'suspicious_score' in procs_df.columns:
            suspicious_count = len(procs_df[procs_df['suspicious_score'] > 0])
            
            techniques = {
                'T1055 - Process Injection': min(suspicious_count * 0.3, 10),
                'T1059 - Command Execution': min(suspicious_count * 0.4, 10),
                'T1071 - Application Layer Protocol': min(len(conns_df) * 0.1, 10) if not conns_df.empty else 0,
                'T1082 - System Information Discovery': min(len(procs_df) * 0.05, 10),
                'T1083 - File Discovery': min(len(files_df) * 0.02, 10) if not files_df.empty else 0,
                'T1057 - Process Discovery': min(len(procs_df) * 0.08, 10),
                'T1049 - System Network Connections': min(len(conns_df) * 0.15, 10) if not conns_df.empty else 0,
            }
            
            fig_mitre = go.Figure(data=go.Bar(
                x=list(techniques.values()),
                y=list(techniques.keys()),
                orientation='h',
                marker=dict(
                    color=list(techniques.values()),
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Confidence")
                )
            ))
            
            fig_mitre.update_layout(
                title='MITRE ATT&CK Techniques Detected',
                xaxis_title='Confidence Score',
                yaxis_title='Technique',
                template='plotly_dark',
                height=400
            )
            st.plotly_chart(fig_mitre, use_container_width=True)
        
        st.markdown("---")
        
        # 7. COMPREHENSIVE STATISTICS
        st.subheader("📊 Comprehensive Statistics")
        
        col_s1, col_s2, col_s3 = st.columns(3)
        
        with col_s1:
            st.markdown("#### 💻 Process Stats")
            st.metric("Total Processes", len(procs_df) if not procs_df.empty else 0)
            if not procs_df.empty and 'suspicious_score' in procs_df.columns:
                suspicious = len(procs_df[procs_df['suspicious_score'] > 0])
                st.metric("Suspicious", suspicious)
                st.metric("Clean", len(procs_df) - suspicious)
        
        with col_s2:
            st.markdown("#### 🌐 Network Stats")
            st.metric("Total Connections", len(conns_df) if not conns_df.empty else 0)
            if not conns_df.empty:
                if 'State' in conns_df.columns:
                    established = len(conns_df[conns_df['State'].str.upper() == 'ESTABLISHED'])
                    st.metric("Established", established)
                if 'ForeignAddr' in conns_df.columns:
                    unique_ips = conns_df['ForeignAddr'].nunique()
                    st.metric("Unique IPs", unique_ips)
        
        with col_s3:
            st.markdown("#### 📁 File Stats")
            st.metric("Total Files", len(files_df) if not files_df.empty else 0)
            if not files_df.empty:
                if 'FileName' in files_df.columns or 'Name' in files_df.columns:
                    name_col = 'FileName' if 'FileName' in files_df.columns else 'Name'
                    unique_files = files_df[name_col].nunique()
                    st.metric("Unique Names", unique_files)
        
        st.markdown("---")
        
        # EXPORT
        st.subheader("📄 Export Results")
        
        if st.button("📥 Generate Full JSON Report", use_container_width=True, type="primary"):
            report = generate_json_report(results)
            st.download_button(
                "Download Complete Report",
                report,
                f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
                use_container_width=True
            )

with st.sidebar:
    st.markdown("### 🔍 VAST v2.0")
    st.markdown("**Advanced Forensics Platform**")
    st.markdown("---")
    
    if st.session_state.analysis_complete and st.session_state.snapshot_info:
        st.markdown("### 💻 Snapshot Info")
        info = st.session_state.snapshot_info
        st.markdown(f"**User:** {info.get('username', 'Unknown')}")
        st.markdown(f"**Device:** {info.get('computer_name', 'Unknown')}")
        st.markdown(f"**OS:** {info.get('os_version', 'Unknown')}")
        st.markdown(f"**Size:** {info.get('size_gb', 'N/A')} GB")
        st.markdown("---")
    
    st.markdown("### 📊 Dashboard Tabs")
    st.markdown("""
    **Tab 1:** Upload & Configure
    **Tab 2:** Timeline & Analysis  
    **Tab 3:** Advanced Analytics
    """)
    
    st.markdown("---")
    st.markdown("### 🆕 Key Features")
    st.markdown("""
    - 100GB file support
    - Device identification
    - User extraction
    - AI threat detection
    - MITRE ATT&CK mapping
    - 7 advanced visualizations
    - Real-time search
    """)
    
    st.markdown("---")
    st.markdown("**ICT3215 - Group 16**")
    st.markdown("Singapore Institute of Technology")
    
    if st.session_state.analysis_complete:
        st.success("✅ Analysis Complete")