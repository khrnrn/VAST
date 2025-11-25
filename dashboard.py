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

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import integration module
try:
    from vast_integration import VASTAnalyzer, run_analysis
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False
    st.warning("⚠️ VAST backend not configured. Place all files in same directory.")

# Page config
st.set_page_config(
    page_title="VAST - Volatile Artifact Snapshot Triage",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #e74c3c;
    }
    .timeline-container {
        background: linear-gradient(90deg, #2c3e50 0%, #34495e 100%);
        padding: 30px;
        border-radius: 10px;
        margin: 20px 0;
    }
    .timeline-event {
        display: inline-block;
        margin: 0 10px;
        text-align: center;
    }
    .timeline-marker {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        margin: 0 auto 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        color: white;
    }
    .process-marker { background-color: #3498db; }
    .network-marker { background-color: #e74c3c; }
    .file-marker { background-color: #2ecc71; }
</style>
""", unsafe_allow_html=True)

# Title
st.markdown('<p class="main-header">🔍 VAST - Volatile Artifact Snapshot Triage</p>', unsafe_allow_html=True)
st.markdown("**Digital Forensics Project - Memory Analysis Tool**")
st.markdown("---")

# Initialize session state
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
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

# Tabs
tab1, tab2 = st.tabs(["📤 Upload Snapshot", "📊 Timeline & Analysis"])

# Tab 1: Upload
with tab1:
    st.header("Upload VM Snapshot")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("1. Select Snapshot File")
        uploaded_file = st.file_uploader(
            "Choose a VM snapshot file",
            type=['vmsn', 'vmem', 'sav'],
            help="Supported: VMware (.vmsn, .vmem), VirtualBox (.sav). Max: 4GB"
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
            ["Windows", "Linux", "macOS"]
        )
        st.session_state.os_type = os_type
    
    st.markdown("---")
    st.subheader("3. Analysis Options")
    
    col3, col4 = st.columns(2)
    
    with col3:
        extract_processes = st.checkbox("Extract Processes", value=True, 
            help="Identify running processes and their metadata")
        extract_network = st.checkbox("Extract Network Connections", value=True,
            help="Capture active network connections and listening ports")
    
    with col4:
        extract_files = st.checkbox("Extract File Handles", value=True,
            help="Find open file handles and recently accessed files")
        extract_registry = st.checkbox("Extract Registry (Windows)", value=(os_type == "Windows"),
            help="Windows only: Extract registry hives and recent activity")
    
    st.markdown("---")
    
    col_btn1, col_btn2, _ = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
            if uploaded_file is None:
                st.error("⚠️ Please upload a snapshot file first!")
            elif not BACKEND_AVAILABLE:
                st.error("⚠️ VAST backend not configured. Ensure all scripts are in the same directory.")
            elif uploaded_file.size > (4096 * 1024 * 1024):
                st.error("⚠️ File exceeds 4GB limit.")
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    tmp_path = tmp_file.name
                
                try:
                    with st.spinner("Analyzing snapshot... This may take several minutes."):
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
                            "extract_modules": False,
                            "extract_secrets": False,
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
                            st.session_state.analysis_complete = True
                        
                        status_text.empty()
                        progress_bar.empty()
                        
                        if backend_results.get("success"):
                            st.success("✅ Analysis completed successfully!")
                            st.info("👉 Go to 'Timeline & Analysis' tab to view results")
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
            st.session_state.analysis_complete = False
            st.rerun()

# Tab 2: Timeline & Analysis
with tab2:
    st.header("Timeline of Events & Forensic Analysis")
    
    # Only show content if analysis is complete
    if not st.session_state.analysis_complete or st.session_state.analysis_results is None:
        st.info("👈 Please upload and analyze a snapshot file in the 'Upload Snapshot' tab first.")
        st.markdown("### What you'll see here:")
        st.markdown("- 🕒 **Horizontal Timeline** - Visual event sequence")
        st.markdown("- 🔍 **Global Search** - Find any artifact instantly")  
        st.markdown("- 📊 **Charts & Graphs** - Statistical analysis")
        st.markdown("- ⚠️ **Threat Detection** - Suspicious artifacts highlighted")
        st.markdown("- 💾 **Export Options** - CSV and JSON downloads")
    else:
        results = st.session_state.analysis_results
        
        # **GLOBAL SEARCH BAR**
        st.subheader("🔍 Search Artifacts")
        search_col1, search_col2 = st.columns([4, 1])
        
        with search_col1:
            search_query = st.text_input(
                "",
                value=st.session_state.search_query,
                placeholder="Search processes, IPs, files, ports, PIDs...",
                key="global_search",
                label_visibility="collapsed"
            )
            st.session_state.search_query = search_query
        
        with search_col2:
            if st.button("Clear Search", use_container_width=True):
                st.session_state.search_query = ""
                st.rerun()
        
        if st.session_state.session_dir:
            with st.expander("📁 Session Directory"):
                st.code(f"{st.session_state.session_dir}")
        
        st.markdown("---")
        
        # Summary metrics
        st.subheader("📈 Analysis Summary")
        
        summary = results.get("summary", {})
        col1, col2, col3, col4 = st.columns(4)
        
        total_processes = summary.get("total_processes", len(results.get('processes', [])))
        total_connections = summary.get("total_connections", len(results.get('connections', [])))
        total_files = summary.get("total_file_objects", len(results.get('file_objects', [])))
        total_artifacts = total_processes + total_connections + total_files
        
        with col1:
            st.metric("Processes", total_processes)
        with col2:
            st.metric("Network", total_connections)
        with col3:
            st.metric("Files", total_files)
        with col4:
            st.metric("Total Artifacts", total_artifacts)
        
        st.markdown("---")
        
        # **HORIZONTAL TIMELINE**
        st.subheader("🕒 Events Timeline")
        
        # Build timeline data
        timeline_events = []
        event_colors = []
        event_types = []
        event_names = []
        event_details = []
        
        # Add process events
        for i, proc in enumerate(results.get("processes", [])[:50]):  # Limit for performance
            timestamp = i  # Use sequence number as x-axis
            name = str(proc.get("ImageFileName") or proc.get("comm") or "Unknown")
            pid = proc.get("PID") or proc.get("pid", "N/A")
            
            timeline_events.append(timestamp)
            event_colors.append('#3498db')  # Blue for processes
            event_types.append('Process')
            event_names.append(name)
            event_details.append(f"PID: {pid}")
        
        # Add network events
        for i, conn in enumerate(results.get("connections", [])[:50]):
            timestamp = len(timeline_events) + i
            name = f"{conn.get('ForeignAddr', 'Unknown')}"
            
            timeline_events.append(timestamp)
            event_colors.append('#e74c3c')  # Red for network
            event_types.append('Network')
            event_names.append(name)
            event_details.append(f"{conn.get('Proto', 'TCP')} {conn.get('State', '')}")
        
        # Add file events
        for i, file_obj in enumerate(results.get("file_objects", [])[:30]):
            timestamp = len(timeline_events) + i
            name = str(file_obj.get("FileName") or "Unknown")[:30]
            
            timeline_events.append(timestamp)
            event_colors.append('#2ecc71')  # Green for files
            event_types.append('File')
            event_names.append(name)
            event_details.append("")
        
        if timeline_events:
            # Apply search filter
            if search_query:
                filtered_indices = [
                    i for i in range(len(timeline_events))
                    if search_query.lower() in event_names[i].lower() or
                       search_query.lower() in event_details[i].lower() or
                       search_query.lower() in event_types[i].lower()
                ]
                
                if filtered_indices:
                    timeline_events = [timeline_events[i] for i in filtered_indices]
                    event_colors = [event_colors[i] for i in filtered_indices]
                    event_types = [event_types[i] for i in filtered_indices]
                    event_names = [event_names[i] for i in filtered_indices]
                    event_details = [event_details[i] for i in filtered_indices]
                    
                    st.info(f"🔍 {len(filtered_indices)} events match '{search_query}'")
                else:
                    st.warning(f"No events match '{search_query}'")
                    timeline_events = []
            
            if timeline_events:
                # Create horizontal timeline
                fig = go.Figure()
                
                # Add trace for each event type
                for event_type, color in [('Process', '#3498db'), ('Network', '#e74c3c'), ('File', '#2ecc71')]:
                    indices = [i for i, t in enumerate(event_types) if t == event_type]
                    if indices:
                        fig.add_trace(go.Scatter(
                            x=[timeline_events[i] for i in indices],
                            y=[1] * len(indices),  # All on same horizontal line
                            mode='markers+text',
                            name=event_type,
                            marker=dict(
                                size=15,
                                color=color,
                                line=dict(width=2, color='white'),
                                symbol='circle'
                            ),
                            text=[event_names[i][:15] for i in indices],
                            textposition='top center',
                            textfont=dict(size=9),
                            customdata=[[event_names[i], event_details[i]] for i in indices],
                            hovertemplate='<b>%{customdata[0]}</b><br>%{customdata[1]}<extra></extra>'
                        ))
                
                # Add horizontal line
                fig.add_shape(
                    type="line",
                    x0=0, x1=max(timeline_events),
                    y0=1, y1=1,
                    line=dict(color="#95a5a6", width=3)
                )
                
                fig.update_layout(
                    title="Event Sequence Timeline",
                    xaxis=dict(
                        title="Event Sequence →",
                        showgrid=False,
                        zeroline=False,
                        range=[-2, max(timeline_events) + 2]
                    ),
                    yaxis=dict(
                        showticklabels=False,
                        showgrid=False,
                        zeroline=False,
                        range=[0.5, 1.5]
                    ),
                    height=300,
                    showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                    template='plotly_dark',
                    hovermode='closest'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Bar charts
                col_chart1, col_chart2 = st.columns(2)
                
                with col_chart1:
                    event_count_df = pd.DataFrame({'Type': event_types}).value_counts().reset_index()
                    event_count_df.columns = ['Type', 'Count']
                    
                    fig_bar = px.bar(
                        event_count_df,
                        x='Type',
                        y='Count',
                        title='Events by Type',
                        color='Type',
                        color_discrete_map={'Process': '#3498db', 'Network': '#e74c3c', 'File': '#2ecc71'}
                    )
                    fig_bar.update_layout(showlegend=False, template='plotly_dark', height=250)
                    st.plotly_chart(fig_bar, use_container_width=True)
                
                with col_chart2:
                    # Suspicious events if available
                    processes_df = pd.DataFrame(results.get("processes", []))
                    if "suspicious_score" in processes_df.columns:
                        susp_df = processes_df[processes_df["suspicious_score"] > 0]
                        if not susp_df.empty:
                            st.metric("⚠️ Suspicious Processes", len(susp_df))
                            fig_susp = px.bar(
                                x=['Suspicious', 'Normal'],
                                y=[len(susp_df), len(processes_df) - len(susp_df)],
                                title='Process Analysis',
                                color=['Suspicious', 'Normal'],
                                color_discrete_map={'Suspicious': '#e74c3c', 'Normal': '#2ecc71'}
                            )
                            fig_susp.update_layout(showlegend=False, template='plotly_dark', height=250)
                            st.plotly_chart(fig_susp, use_container_width=True)
                        else:
                            st.success("✅ No suspicious processes detected")
                    else:
                        st.info("No threat analysis available")
        
        st.markdown("---")
        
        # **PROCESSES**
        if results.get("processes"):
            st.subheader("💻 Process Analysis")
            
            processes_df = pd.DataFrame(results["processes"])
            
            if search_query:
                mask = processes_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_processes = processes_df[mask]
            else:
                filtered_processes = processes_df
            
            col_p1, col_p2, col_p3 = st.columns(3)
            
            with col_p1:
                st.metric("Total Processes", len(filtered_processes))
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
                    with st.expander(f"⚠️ Suspicious Processes ({len(susp_procs)})", expanded=True):
                        st.dataframe(susp_procs.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Processes"):
                st.dataframe(filtered_processes, use_container_width=True, height=400)
                csv = filtered_processes.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "processes.csv", "text/csv")
        
        st.markdown("---")
        
        # **NETWORK**
        if results.get("connections"):
            st.subheader("🌐 Network Analysis")
            
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
                        fig = px.bar(x=ips.values, y=ips.index, orientation='h', title='Top Destination IPs')
                        fig.update_layout(template='plotly_dark', height=250)
                        st.plotly_chart(fig, use_container_width=True)
                
                with col_viz2:
                    ports = filtered_conns["LocalPort"].value_counts().head(10)
                    if not ports.empty:
                        fig = px.bar(x=ports.values, y=ports.index.astype(str), orientation='h', title='Top Local Ports')
                        fig.update_layout(template='plotly_dark', height=250)
                        st.plotly_chart(fig, use_container_width=True)
            
            if "suspicious_score" in filtered_conns.columns:
                susp_conns = filtered_conns[filtered_conns["suspicious_score"] > 0]
                if not susp_conns.empty:
                    with st.expander(f"⚠️ Suspicious Connections ({len(susp_conns)})", expanded=True):
                        st.dataframe(susp_conns.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Network Connections"):
                st.dataframe(filtered_conns, use_container_width=True, height=400)
                csv = filtered_conns.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "connections.csv", "text/csv")
        
        st.markdown("---")
        
        # **FILES**
        if results.get("file_objects"):
            st.subheader("📁 File Analysis")
            
            files_df = pd.DataFrame(results["file_objects"])
            
            if search_query:
                mask = files_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                filtered_files = files_df[mask]
            else:
                filtered_files = files_df
            
            st.metric("File Objects Found", len(filtered_files))
            
            with st.expander("📋 All File Objects"):
                st.dataframe(filtered_files, use_container_width=True, height=400)
                csv = filtered_files.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "files.csv", "text/csv")
        
        st.markdown("---")
        
        # **EXPORT**
        st.subheader("📄 Export Results")
        
        col_ex1, col_ex2 = st.columns(2)
        
        with col_ex1:
            if st.button("📥 Generate Full JSON Report", use_container_width=True):
                report = generate_json_report(results)
                st.download_button(
                    "Download JSON Report",
                    report,
                    f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "application/json",
                    use_container_width=True
                )
        
        with col_ex2:
            if st.session_state.session_dir:
                st.info(f"📁 Session: {Path(st.session_state.session_dir).name}")

# Helper function
def generate_json_report(results):
    """Generate JSON report"""
    report = {
        'metadata': {
            'date': datetime.now().isoformat(),
            'tool': 'VAST v1.0',
            'os': st.session_state.os_type if st.session_state.os_type else 'Unknown',
            'session': st.session_state.session_dir if st.session_state.session_dir else 'N/A'
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
    - 📊 Horizontal timeline
    - 🔍 Global search
    - 📈 Statistical charts
    - 🎯 Threat detection
    - 💾 Multiple exports
    """)
    
    st.markdown("---")
    st.markdown("### Analysis Options")
    with st.expander("ℹ️ What do they mean?"):
        st.markdown("""
        **Extract Processes:**
        - Running processes and their metadata
        - Process IDs, parent relationships
        - Command-line arguments
        
        **Extract Network:**
        - Active TCP/UDP connections
        - Listening ports and services
        - Remote IP addresses
        
        **Extract File Handles:**
        - Open file descriptors
        - Recently accessed files
        - File system activity
        
        **Extract Registry (Windows):**
        - Registry hives in memory
        - Recent document access
        - User activity traces
        """)
    
    st.markdown("---")
    st.markdown("**ICT3215 - Group 16**")
    st.markdown("Singapore Institute of Technology")
    
    if st.session_state.analysis_complete:
        st.markdown("---")
        st.success("✅ Analysis Complete")