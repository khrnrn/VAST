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

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import our integration module
try:
    from vast_integration import VASTAnalyzer, run_analysis
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False
    st.warning("⚠️ VAST backend not fully configured. Running in demo mode.")

# Page configuration
st.set_page_config(
    page_title="VAST - Volatile Artifact Snapshot Triage",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #e74c3c;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #95a5a6;
    }
</style>
""", unsafe_allow_html=True)

# Title
st.markdown('<p class="main-header">🔍 VAST - Volatile Artifact Snapshot Triage</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Digital Forensics Project - Memory Analysis Tool</p>', unsafe_allow_html=True)
st.markdown("---")

# Initialize session state
if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None
if 'os_type' not in st.session_state:
    st.session_state.os_type = None
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'backend_results' not in st.session_state:
    st.session_state.backend_results = None
if 'session_dir' not in st.session_state:
    st.session_state.session_dir = None
if 'search_query' not in st.session_state:
    st.session_state.search_query = ""

# Create tabs
tab1, tab2 = st.tabs(["📤 Upload Snapshot", "📊 Timeline & Analysis"])

# Tab 1: Upload Snapshot
with tab1:
    st.header("Upload VM Snapshot")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("1. Select Snapshot File")
        uploaded_file = st.file_uploader(
            "Choose a VM snapshot file",
            type=['vmsn', 'vmem', 'sav'],
            help="Supported formats: VMware (.vmsn, .vmem) and VirtualBox (.sav). Maximum file size: 4GB"
        )
        
        if uploaded_file is not None:
            file_size_mb = uploaded_file.size / (1024 * 1024)
            file_size_gb = file_size_mb / 1024
            
            if file_size_mb > 4096:
                st.error(f"⚠️ File too large: {file_size_gb:.2f} GB. Maximum is 4GB.")
                st.session_state.uploaded_file = None
            else:
                st.success(f"✅ File uploaded: {uploaded_file.name}")
                st.session_state.uploaded_file = uploaded_file
                
                if file_size_mb < 1024:
                    st.info(f"**File Size:** {file_size_mb:.2f} MB")
                else:
                    st.info(f"**File Size:** {file_size_gb:.2f} GB")
                
                if file_size_mb > 2048:
                    st.warning(f"⚠️ Large file ({file_size_gb:.2f} GB). Analysis may take 20-30 minutes.")
    
    with col2:
        st.subheader("2. Select Guest OS")
        os_type = st.selectbox(
            "Choose the operating system",
            ["Windows", "Linux", "macOS"],
            help="Select the OS that was running in the VM snapshot"
        )
        st.session_state.os_type = os_type
        
        os_info = {
            "Windows": "🪟 Analyzing Windows processes, registry, and network",
            "Linux": "🐧 Analyzing Linux processes, kernel structures",
            "macOS": "🍎 Analyzing macOS processes, system frameworks"
        }
        st.info(os_info[os_type])
    
    st.markdown("---")
    st.subheader("3. Analysis Options")
    
    col3, col4, col5 = st.columns(3)
    
    with col3:
        extract_processes = st.checkbox("Extract Processes", value=True)
        extract_network = st.checkbox("Extract Network Connections", value=True)
    
    with col4:
        extract_files = st.checkbox("Extract File Handles", value=True)
        extract_registry = st.checkbox("Extract Registry (Windows)", value=(os_type == "Windows"))
    
    with col5:
        extract_modules = st.checkbox("Extract Loaded Modules", value=False)
        extract_secrets = st.checkbox("Scan for Secrets", value=False)
    
    st.markdown("---")
    
    col_btn1, col_btn2, _ = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
            if uploaded_file is None:
                st.error("⚠️ Please upload a snapshot file first!")
            elif not BACKEND_AVAILABLE:
                st.error("⚠️ VAST backend not configured.")
            elif uploaded_file.size > (4096 * 1024 * 1024):
                st.error("⚠️ File exceeds 4GB limit.")
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    tmp_path = tmp_file.name
                
                try:
                    with st.spinner("Analyzing snapshot..."):
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        def update_progress(message: str, progress: float):
                            status_text.text(message)
                            progress_bar.progress(progress)
                        
                        options = {
                            "extract_processes": extract_processes,
                            "extract_network": extract_network,
                            "extract_files": extract_files,
                            "extract_registry": extract_registry and (os_type == "Windows"),
                            "extract_modules": extract_modules,
                            "extract_secrets": extract_secrets,
                        }
                        
                        backend_results = run_analysis(
                            snapshot_path=tmp_path,
                            os_type=os_type.lower(),
                            options=options,
                            progress_callback=update_progress
                        )
                        
                        st.session_state.backend_results = backend_results
                        
                        if backend_results.get("success") and backend_results.get("session_dir"):
                            analyzer = VASTAnalyzer()
                            display_results = analyzer.load_results(Path(backend_results["session_dir"]))
                            st.session_state.analysis_results = display_results
                            st.session_state.session_dir = backend_results["session_dir"]
                        
                        status_text.empty()
                        progress_bar.empty()
                        
                        if backend_results.get("success"):
                            st.success("✅ Analysis completed successfully!")
                            st.balloons()
                            
                            if backend_results.get("warnings"):
                                with st.expander("⚠️ Warnings"):
                                    for warning in backend_results["warnings"]:
                                        st.warning(warning)
                        else:
                            st.error("❌ Analysis failed:")
                            for error in backend_results.get("errors", ["Unknown error"]):
                                st.error(error)
                
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
    
    with col_btn2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.uploaded_file = None
            st.session_state.analysis_results = None
            st.rerun()

# Tab 2: Timeline & Analysis
with tab2:
    st.header("Timeline of Events & Forensic Analysis")
    
    if st.session_state.analysis_results is None:
        st.info("👈 Please upload and analyze a snapshot file first.")
    else:
        results = st.session_state.analysis_results
        
        # **GLOBAL SEARCH BAR**
        st.subheader("🔍 Search All Artifacts")
        search_col1, search_col2 = st.columns([4, 1])
        
        with search_col1:
            search_query = st.text_input(
                "",
                value=st.session_state.search_query,
                placeholder="Search processes, IPs, files, registry keys...",
                key="global_search",
                label_visibility="collapsed"
            )
            st.session_state.search_query = search_query
        
        with search_col2:
            if st.button("Clear", use_container_width=True):
                st.session_state.search_query = ""
                st.rerun()
        
        if st.session_state.session_dir:
            with st.expander("📁 Session Info"):
                st.code(f"{st.session_state.session_dir}")
        
        st.markdown("---")
        
        # Summary metrics
        st.subheader("📈 Summary")
        
        summary = results.get("summary", {})
        col1, col2, col3, col4 = st.columns(4)
        
        total_processes = summary.get("total_processes", len(results.get('processes', [])))
        total_connections = summary.get("total_connections", len(results.get('connections', [])))
        total_files = summary.get("total_file_objects", len(results.get('file_objects', [])))
        total_artifacts = summary.get("total_artifacts", total_processes + total_connections + total_files)
        
        with col1:
            st.metric("Processes", total_processes)
        with col2:
            st.metric("Network", total_connections)
        with col3:
            st.metric("Files", total_files)
        with col4:
            st.metric("Total Artifacts", total_artifacts)
        
        st.markdown("---")
        
        # **UNIFIED TIMELINE**
        st.subheader("🕒 Events Timeline")
        
        timeline_events = []
        
        # Add process events
        for proc in results.get("processes", []):
            timeline_events.append({
                "Type": "Process",
                "Name": str(proc.get("ImageFileName") or proc.get("comm") or "Unknown"),
                "PID": proc.get("PID") or proc.get("pid"),
                "Details": f"PPID: {proc.get('PPID') or proc.get('ppid', 'N/A')}",
                "Suspicious": proc.get("suspicious_score", 0),
                "Tags": ", ".join(proc.get("tags", []))
            })
        
        # Add network events
        for conn in results.get("connections", []):
            timeline_events.append({
                "Type": "Network",
                "Name": f"{conn.get('LocalAddr', '')}:{conn.get('LocalPort', '')} → {conn.get('ForeignAddr', '')}:{conn.get('ForeignPort', '')}",
                "PID": conn.get("PID") or conn.get("pid"),
                "Details": f"{conn.get('Proto', 'Unknown')} {conn.get('State', '')}",
                "Suspicious": conn.get("suspicious_score", 0),
                "Tags": ", ".join(conn.get("tags", []))
            })
        
        # Add file events
        for file_obj in results.get("file_objects", [])[:100]:  # Limit to 100 for performance
            timeline_events.append({
                "Type": "File",
                "Name": str(file_obj.get("FileName") or file_obj.get("Name") or "Unknown")[:80],
                "PID": file_obj.get("PID") or "N/A",
                "Details": "",
                "Suspicious": 0,
                "Tags": ""
            })
        
        if timeline_events:
            timeline_df = pd.DataFrame(timeline_events)
            
            # Apply search
            if search_query:
                mask = timeline_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_timeline = timeline_df[mask]
                st.info(f"🔍 {len(filtered_timeline)} events match '{search_query}'")
            else:
                filtered_timeline = timeline_df
            
            if len(filtered_timeline) > 0:
                # Timeline chart
                fig = go.Figure()
                
                for event_type in ['Process', 'Network', 'File']:
                    df_type = filtered_timeline[filtered_timeline['Type'] == event_type]
                    if len(df_type) > 0:
                        color_map = {'Process': '#3498db', 'Network': '#e74c3c', 'File': '#2ecc71'}
                        
                        fig.add_trace(go.Scatter(
                            x=list(range(len(df_type))),
                            y=df_type['Type'],
                            mode='markers',
                            name=event_type,
                            marker=dict(
                                size=df_type['Suspicious'].fillna(0) * 2 + 8,
                                color=color_map[event_type],
                                line=dict(width=1, color='white')
                            ),
                            text=df_type['Name'],
                            customdata=df_type[['PID', 'Details', 'Tags']],
                            hovertemplate='<b>%{text}</b><br>PID: %{customdata[0]}<br>%{customdata[1]}<extra></extra>'
                        ))
                
                fig.update_layout(
                    title="Event Timeline",
                    xaxis_title="Sequence",
                    yaxis_title="Type",
                    height=350,
                    showlegend=True,
                    template='plotly_dark'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Bar charts
                col_chart1, col_chart2 = st.columns(2)
                
                with col_chart1:
                    event_counts = filtered_timeline['Type'].value_counts()
                    fig_bar = px.bar(
                        x=event_counts.index,
                        y=event_counts.values,
                        labels={'x': 'Type', 'y': 'Count'},
                        title='Events by Type',
                        color=event_counts.index,
                        color_discrete_map={'Process': '#3498db', 'Network': '#e74c3c', 'File': '#2ecc71'}
                    )
                    fig_bar.update_layout(showlegend=False, template='plotly_dark', height=250)
                    st.plotly_chart(fig_bar, use_container_width=True)
                
                with col_chart2:
                    suspicious_counts = filtered_timeline[filtered_timeline['Suspicious'] > 0]['Type'].value_counts()
                    if not suspicious_counts.empty:
                        fig_susp = px.bar(
                            x=suspicious_counts.index,
                            y=suspicious_counts.values,
                            title='Suspicious Events',
                            color=suspicious_counts.index,
                            color_discrete_map={'Process': '#e74c3c', 'Network': '#c0392b', 'File': '#e67e22'}
                        )
                        fig_susp.update_layout(showlegend=False, template='plotly_dark', height=250)
                        st.plotly_chart(fig_susp, use_container_width=True)
                    else:
                        st.success("✅ No suspicious events")
                
                # Timeline table
                with st.expander("📋 Timeline Details", expanded=False):
                    st.dataframe(filtered_timeline, use_container_width=True, height=400)
                    
                    csv = filtered_timeline.to_csv(index=False)
                    st.download_button(
                        "📥 Download Timeline CSV",
                        csv,
                        f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        "text/csv"
                    )
        
        st.markdown("---")
        
        # **PROCESSES**
        if results.get("processes"):
            st.subheader("💻 Processes")
            
            processes_df = pd.DataFrame(results["processes"])
            
            if search_query:
                mask = processes_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_processes = processes_df[mask]
            else:
                filtered_processes = processes_df
            
            col_p1, col_p2, col_p3 = st.columns(3)
            
            with col_p1:
                st.metric("Total", len(filtered_processes))
            with col_p2:
                if "suspicious_score" in filtered_processes.columns:
                    susp = filtered_processes[filtered_processes["suspicious_score"] > 0]
                    st.metric("Suspicious", len(susp))
            with col_p3:
                if "Wow64" in filtered_processes.columns:
                    wow = filtered_processes[filtered_processes["Wow64"] == True]
                    st.metric("WoW64", len(wow))
            
            if "suspicious_score" in filtered_processes.columns:
                susp_procs = filtered_processes[filtered_processes["suspicious_score"] > 0]
                if not susp_procs.empty:
                    with st.expander(f"⚠️ Suspicious ({len(susp_procs)})", expanded=True):
                        st.dataframe(susp_procs.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Processes"):
                st.dataframe(filtered_processes, use_container_width=True, height=400)
                csv = filtered_processes.to_csv(index=False)
                st.download_button("📥 CSV", csv, "processes.csv", "text/csv")
        
        st.markdown("---")
        
        # **NETWORK**
        if results.get("connections"):
            st.subheader("🌐 Network")
            
            connections_df = pd.DataFrame(results["connections"])
            
            if search_query:
                mask = connections_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_conns = connections_df[mask]
            else:
                filtered_conns = connections_df
            
            col_n1, col_n2, col_n3, col_n4 = st.columns(4)
            
            with col_n1:
                st.metric("Total", len(filtered_conns))
            with col_n2:
                if "State" in filtered_conns.columns:
                    est = filtered_conns[filtered_conns["State"].str.upper() == "ESTABLISHED"]
                    st.metric("Established", len(est))
            with col_n3:
                if "State" in filtered_conns.columns:
                    listen = filtered_conns[filtered_conns["State"].str.upper() == "LISTENING"]
                    st.metric("Listening", len(listen))
            with col_n4:
                if "suspicious_score" in filtered_conns.columns:
                    susp = filtered_conns[filtered_conns["suspicious_score"] > 0]
                    st.metric("Suspicious", len(susp))
            
            # Charts
            if "ForeignAddr" in filtered_conns.columns:
                col_viz1, col_viz2 = st.columns(2)
                
                with col_viz1:
                    ips = filtered_conns["ForeignAddr"].value_counts().head(10)
                    if not ips.empty:
                        fig = px.bar(x=ips.values, y=ips.index, orientation='h', title='Top IPs')
                        fig.update_layout(template='plotly_dark', height=250)
                        st.plotly_chart(fig, use_container_width=True)
                
                with col_viz2:
                    ports = filtered_conns["LocalPort"].value_counts().head(10)
                    if not ports.empty:
                        fig = px.bar(x=ports.values, y=ports.index.astype(str), orientation='h', title='Top Ports')
                        fig.update_layout(template='plotly_dark', height=250)
                        st.plotly_chart(fig, use_container_width=True)
            
            if "suspicious_score" in filtered_conns.columns:
                susp_conns = filtered_conns[filtered_conns["suspicious_score"] > 0]
                if not susp_conns.empty:
                    with st.expander(f"⚠️ Suspicious ({len(susp_conns)})", expanded=True):
                        st.dataframe(susp_conns.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Connections"):
                st.dataframe(filtered_conns, use_container_width=True, height=400)
                csv = filtered_conns.to_csv(index=False)
                st.download_button("📥 CSV", csv, "connections.csv", "text/csv")
        
        st.markdown("---")
        
        # **FILES**
        if results.get("file_objects"):
            st.subheader("📁 Files")
            
            files_df = pd.DataFrame(results["file_objects"])
            
            if search_query:
                mask = files_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_files = files_df[mask]
            else:
                filtered_files = files_df
            
            st.metric("File Objects", len(filtered_files))
            
            with st.expander("📋 File Objects"):
                st.dataframe(filtered_files, use_container_width=True, height=400)
                csv = filtered_files.to_csv(index=False)
                st.download_button("📥 CSV", csv, "files.csv", "text/csv")
        
        st.markdown("---")
        
        # **EXPORT**
        st.subheader("📄 Export")
        
        col_ex1, col_ex2 = st.columns(2)
        
        with col_ex1:
            report = generate_json_report(results)
            st.download_button(
                "📥 Full JSON Report",
                report,
                f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
                use_container_width=True
            )
        
        with col_ex2:
            if st.session_state.session_dir:
                st.info(f"📁 {Path(st.session_state.session_dir).name}")

def generate_json_report(results):
    """Generate JSON report"""
    report = {
        'metadata': {
            'date': datetime.now().isoformat(),
            'tool': 'VAST v1.0',
            'os': st.session_state.os_type,
            'session': st.session_state.session_dir
        },
        'summary': results.get('summary', {}),
        'artifacts': {
            'processes': results.get('processes', []),
            'connections': results.get('connections', []),
            'files': results.get('file_objects', [])
        }
    }
    return json.dumps(report, indent=2)

# Sidebar
with st.sidebar:
    st.markdown("### 🔍 VAST")
    st.markdown("**Volatile Artifact Snapshot Triage**")
    st.markdown("---")
    
    st.markdown("### Features")
    st.markdown("""
    - 📊 Interactive timeline
    - 🔍 Global search
    - 📈 Statistical charts
    - 🎯 Threat detection
    - 💾 CSV/JSON export
    """)
    
    st.markdown("---")
    st.markdown("### Quick Steps")
    st.markdown("""
    1. Upload snapshot
    2. Select OS
    3. Start analysis
    4. View timeline
    5. Search artifacts
    6. Export results
    """)
    
    st.markdown("---")
    st.markdown("**ICT3215 - Group 16**")
    st.markdown("SIT 2024")