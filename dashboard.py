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

# Page config
st.set_page_config(
    page_title="VAST - Volatile Artifact Snapshot Triage",
    page_icon="🔍",
    layout="wide"
)

# Title
st.markdown("# 🔍 VAST - Volatile Artifact Snapshot Triage")
st.markdown("**Digital Forensics Project - Memory Analysis Tool**")
st.markdown("---")

# Initialize session state
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'session_dir' not in st.session_state:
    st.session_state.session_dir = None
if 'search_query' not in st.session_state:
    st.session_state.search_query = ""

# Helper function
def generate_json_report(results):
    """Generate JSON report"""
    report = {
        'metadata': {
            'date': datetime.now().isoformat(),
            'tool': 'VAST v1.0',
            'os': st.session_state.get('os_type', 'Unknown'),
            'session': st.session_state.get('session_dir', 'N/A')
        },
        'summary': results.get('summary', {}),
        'artifacts': {
            'processes': results.get('processes', []),
            'connections': results.get('connections', []),
            'files': results.get('file_objects', [])
        }
    }
    return json.dumps(report, indent=2)

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
            else:
                st.success(f"✅ File uploaded: {uploaded_file.name}")
                
                if file_size_mb < 1024:
                    st.info(f"**File Size:** {file_size_mb:.2f} MB")
                else:
                    st.info(f"**File Size:** {file_size_gb:.2f} GB")
                
                if file_size_mb > 2048:
                    st.warning(f"⚠️ Large file ({file_size_gb:.2f} GB). Analysis may take 20-30 minutes.")
    
    with col2:
        st.subheader("2. Select Guest OS")
        os_type = st.selectbox("Choose the operating system", ["Windows", "Linux", "macOS"])
    
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
                st.error("⚠️ VAST backend not configured.")
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
                        
                        if backend_results.get("success") and backend_results.get("session_dir"):
                            analyzer = VASTAnalyzer()
                            display_results = analyzer.load_results(Path(backend_results["session_dir"]))
                            st.session_state.analysis_results = display_results
                            st.session_state.session_dir = backend_results["session_dir"]
                            st.session_state.os_type = os_type
                            st.session_state.analysis_complete = True
                        
                        status_text.empty()
                        progress_bar.empty()
                        
                        if backend_results.get("success"):
                            st.success("✅ Analysis completed successfully!")
                            st.info("👉 Go to 'Timeline & Analysis' tab to view results")
                            st.balloons()
                        else:
                            st.error("❌ Analysis failed")
                
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
    
    with col_btn2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.analysis_complete = False
            st.session_state.analysis_results = None
            st.rerun()

# Tab 2: Timeline & Analysis - ONLY SHOW IF ANALYSIS COMPLETE
with tab2:
    if not st.session_state.analysis_complete:
        # Show placeholder BEFORE analysis
        st.info("👈 **Please complete analysis in the 'Upload Snapshot' tab first**")
        st.markdown("---")
        st.markdown("### 📊 What You'll See After Analysis:")
        st.markdown("""
        - **🕒 Interactive Timeline** - Visual event sequence showing processes, network, and files
        - **🔍 Global Search** - Instantly find any artifact across all data
        - **📈 Statistical Charts** - Distribution graphs and suspicious event detection
        - **⚠️ Threat Analysis** - Automatically highlighted suspicious processes and connections
        - **💾 Export Options** - Download results as CSV or JSON for further analysis
        """)
        st.markdown("---")
        st.info("💡 **Tip:** Analysis typically takes 5-15 minutes depending on snapshot size")
        
    else:
        # ONLY SHOW AFTER ANALYSIS COMPLETE
        results = st.session_state.analysis_results
        
        st.header("Timeline of Events & Forensic Analysis")
        
        # Search bar
        st.subheader("🔍 Search Artifacts")
        search_col1, search_col2 = st.columns([4, 1])
        
        with search_col1:
            search_query = st.text_input(
                "",
                value=st.session_state.search_query,
                placeholder="Search processes, IPs, files, ports...",
                key="global_search",
                label_visibility="collapsed"
            )
            st.session_state.search_query = search_query
        
        with search_col2:
            if st.button("Clear", use_container_width=True):
                st.session_state.search_query = ""
                st.rerun()
        
        st.markdown("---")
        
        # Summary
        st.subheader("📈 Summary")
        summary = results.get("summary", {})
        col1, col2, col3, col4 = st.columns(4)
        
        total_processes = len(results.get('processes', []))
        total_connections = len(results.get('connections', []))
        total_files = len(results.get('file_objects', []))
        
        col1.metric("Processes", total_processes)
        col2.metric("Network", total_connections)
        col3.metric("Files", total_files)
        col4.metric("Total", total_processes + total_connections + total_files)
        
        st.markdown("---")
        
        # IMPROVED TIMELINE
        st.subheader("🕒 Events Timeline")
        
        # Prepare timeline data
        timeline_data = []
        
        # Processes
        for i, proc in enumerate(results.get("processes", [])[:50]):
            name = str(proc.get("ImageFileName") or proc.get("comm") or "Unknown")
            timeline_data.append({
                'sequence': i,
                'type': 'Process',
                'name': name[:30],
                'color': '#3498db',
                'icon': '⚙️',
                'details': f"PID: {proc.get('PID') or proc.get('pid', 'N/A')}"
            })
        
        # Network
        offset = len(timeline_data)
        for i, conn in enumerate(results.get("connections", [])[:50]):
            addr = conn.get('ForeignAddr', 'Unknown')
            timeline_data.append({
                'sequence': offset + i,
                'type': 'Network',
                'name': addr[:30],
                'color': '#e74c3c',
                'icon': '🌐',
                'details': f"{conn.get('Proto', 'TCP')} - {conn.get('State', '')}"
            })
        
        # Files
        offset = len(timeline_data)
        for i, file_obj in enumerate(results.get("file_objects", [])[:30]):
            name = str(file_obj.get("FileName") or "Unknown")
            timeline_data.append({
                'sequence': offset + i,
                'type': 'File',
                'name': name[:30],
                'color': '#2ecc71',
                'icon': '📁',
                'details': ''
            })
        
        if timeline_data:
            df = pd.DataFrame(timeline_data)
            
            # Filter by search
            if search_query:
                mask = df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                df = df[mask]
                if len(df) > 0:
                    st.info(f"🔍 Found {len(df)} events matching '{search_query}'")
                else:
                    st.warning(f"No matches for '{search_query}'")
            
            if len(df) > 0:
                # Create arrow-style timeline
                fig = go.Figure()
                
                for event_type in ['Process', 'Network', 'File']:
                    df_type = df[df['type'] == event_type]
                    if len(df_type) > 0:
                        fig.add_trace(go.Scatter(
                            x=df_type['sequence'],
                            y=[1] * len(df_type),
                            mode='markers+text',
                            name=f"{df_type.iloc[0]['icon']} {event_type}",
                            marker=dict(
                                size=20,
                                color=df_type.iloc[0]['color'],
                                line=dict(width=2, color='white'),
                                symbol='circle'
                            ),
                            text=df_type['name'],
                            textposition='top center',
                            textfont=dict(size=8),
                            customdata=df_type[['name', 'details']],
                            hovertemplate='<b>%{customdata[0]}</b><br>%{customdata[1]}<extra></extra>'
                        ))
                
                # Timeline arrow
                if len(df) > 1:
                    fig.add_annotation(
                        x=max(df['sequence']),
                        y=1,
                        ax=0,
                        ay=1,
                        xref='x',
                        yref='y',
                        axref='x',
                        ayref='y',
                        showarrow=True,
                        arrowhead=2,
                        arrowsize=1.5,
                        arrowwidth=3,
                        arrowcolor='#95a5a6'
                    )
                
                fig.update_layout(
                    title="Event Sequence Timeline (Hover for details)",
                    xaxis=dict(
                        title="← Earlier Events | Event Sequence | Later Events →",
                        showgrid=True,
                        gridcolor='#2c3e50',
                        zeroline=False
                    ),
                    yaxis=dict(
                        showticklabels=False,
                        showgrid=False,
                        zeroline=False,
                        range=[0.7, 1.3]
                    ),
                    height=350,
                    showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
                    template='plotly_dark',
                    hovermode='closest',
                    plot_bgcolor='#1e1e1e',
                    paper_bgcolor='#0e1117'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Stats
                col_c1, col_c2 = st.columns(2)
                
                with col_c1:
                    counts = df['type'].value_counts()
                    fig_bar = px.bar(
                        x=counts.index, y=counts.values,
                        title='Events by Type',
                        labels={'x': 'Type', 'y': 'Count'},
                        color=counts.index,
                        color_discrete_map={'Process': '#3498db', 'Network': '#e74c3c', 'File': '#2ecc71'}
                    )
                    fig_bar.update_layout(showlegend=False, template='plotly_dark', height=300)
                    st.plotly_chart(fig_bar, use_container_width=True)
                
                with col_c2:
                    procs_df = pd.DataFrame(results.get("processes", []))
                    if "suspicious_score" in procs_df.columns and not procs_df.empty:
                        susp_count = len(procs_df[procs_df["suspicious_score"] > 0])
                        norm_count = len(procs_df) - susp_count
                        if susp_count > 0:
                            fig_susp = px.bar(
                                x=['⚠️ Suspicious', '✅ Normal'],
                                y=[susp_count, norm_count],
                                title='Process Analysis',
                                color=['Suspicious', 'Normal'],
                                color_discrete_map={'Suspicious': '#e74c3c', 'Normal': '#2ecc71'}
                            )
                            fig_susp.update_layout(showlegend=False, template='plotly_dark', height=300)
                            st.plotly_chart(fig_susp, use_container_width=True)
                        else:
                            st.success("✅ No suspicious processes detected")
                    else:
                        st.info("No threat analysis available")
        
        st.markdown("---")
        
        # PROCESSES
        if results.get("processes"):
            st.subheader("💻 Process Analysis")
            procs_df = pd.DataFrame(results["processes"])
            
            if search_query:
                mask = procs_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                procs_df = procs_df[mask]
            
            # Remove __children column if it exists
            if '__children' in procs_df.columns:
                procs_df = procs_df.drop(columns=['__children'])
            
            col_p1, col_p2 = st.columns(2)
            col_p1.metric("Total Processes", len(procs_df))
            
            if "suspicious_score" in procs_df.columns:
                susp = procs_df[procs_df["suspicious_score"] > 0]
                col_p2.metric("⚠️ Suspicious", len(susp))
                
                if not susp.empty:
                    with st.expander(f"⚠️ Suspicious Processes ({len(susp)})", expanded=True):
                        st.dataframe(susp.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Processes"):
                st.dataframe(procs_df, use_container_width=True, height=400)
                csv = procs_df.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "processes.csv", "text/csv")
        
        st.markdown("---")
        
        # NETWORK
        if results.get("connections"):
            st.subheader("🌐 Network Analysis")
            conns_df = pd.DataFrame(results["connections"])
            
            if search_query:
                mask = conns_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                conns_df = conns_df[mask]
            
            # Remove __children if exists
            if '__children' in conns_df.columns:
                conns_df = conns_df.drop(columns=['__children'])
            
            col_n1, col_n2, col_n3 = st.columns(3)
            col_n1.metric("Total", len(conns_df))
            
            if "State" in conns_df.columns:
                est = conns_df[conns_df["State"].str.upper() == "ESTABLISHED"]
                col_n2.metric("Established", len(est))
                listen = conns_df[conns_df["State"].str.upper() == "LISTENING"]
                col_n3.metric("Listening", len(listen))
            
            if "suspicious_score" in conns_df.columns:
                susp = conns_df[conns_df["suspicious_score"] > 0]
                if not susp.empty:
                    with st.expander(f"⚠️ Suspicious ({len(susp)})", expanded=True):
                        st.dataframe(susp.sort_values("suspicious_score", ascending=False), height=250)
            
            with st.expander("📋 All Connections"):
                st.dataframe(conns_df, use_container_width=True, height=400)
                csv = conns_df.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "connections.csv", "text/csv")
        
        st.markdown("---")
        
        # FILES
        if results.get("file_objects"):
            st.subheader("📁 File Analysis")
            files_df = pd.DataFrame(results["file_objects"])
            
            if search_query:
                mask = files_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)
                files_df = files_df[mask]
            
            # Remove __children if exists
            if '__children' in files_df.columns:
                files_df = files_df.drop(columns=['__children'])
            
            st.metric("File Objects", len(files_df))
            
            with st.expander("📋 All File Objects"):
                st.dataframe(files_df, use_container_width=True, height=400)
                csv = files_df.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "files.csv", "text/csv")
        
        st.markdown("---")
        
        # EXPORT
        st.subheader("📄 Export Results")
        col_ex1, col_ex2 = st.columns(2)
        
        with col_ex1:
            if st.button("📥 Generate JSON Report", use_container_width=True):
                try:
                    report = generate_json_report(results)
                    st.download_button(
                        "Download Report",
                        report,
                        f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        "application/json",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"Error generating report: {str(e)}")
        
        with col_ex2:
            if st.session_state.session_dir:
                st.info(f"📁 {Path(st.session_state.session_dir).name}")

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
    st.markdown("**ICT3215 - Group 16**")
    st.markdown("SIT 2024")
    
    if st.session_state.analysis_complete:
        st.success("✅ Analysis Complete")