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
    layout="wide"
)

# Title and description
st.title("🔍 VAST - Volatile Artifact Snapshot Triage")
st.markdown("**Digital Forensics Project - Memory Analysis Tool**")
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

# Create tabs
tab1, tab2 = st.tabs(["📤 Upload Snapshot", "📊 Timeline of Events"])

# Tab 1: Upload Snapshot and Choose OS
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
            # Check file size (4GB = 4096 MB)
            file_size_mb = uploaded_file.size / (1024 * 1024)  # Convert to MB
            file_size_gb = file_size_mb / 1024  # Convert to GB
            
            if file_size_mb > 4096:  # 4GB limit
                st.error(f"⚠️ File too large: {file_size_gb:.2f} GB. Maximum file size is 4GB.")
                st.warning("Please use a smaller snapshot or compress the file before uploading.")
                st.session_state.uploaded_file = None
            else:
                st.success(f"✅ File uploaded: {uploaded_file.name}")
                st.session_state.uploaded_file = uploaded_file
                
                # Display file details with progress bar
                if file_size_mb < 1024:
                    st.info(f"**File Size:** {file_size_mb:.2f} MB")
                else:
                    st.info(f"**File Size:** {file_size_gb:.2f} GB")
                
                # Show warning for large files
                if file_size_mb > 2048:  # > 2GB
                    st.warning(f"⚠️ Large file detected ({file_size_gb:.2f} GB). Analysis may take 20-30 minutes.")
    
    with col2:
        st.subheader("2. Select Guest OS")
        os_type = st.selectbox(
            "Choose the operating system",
            ["Windows", "Linux", "macOS"],
            help="Select the OS that was running in the VM snapshot"
        )
        st.session_state.os_type = os_type
        
        # Display OS-specific information
        os_info = {
            "Windows": "🪟 Analyzing Windows processes, registry, and network connections",
            "Linux": "🐧 Analyzing Linux processes, kernel structures, and system calls",
            "macOS": "🍎 Analyzing macOS processes, system frameworks, and security features"
        }
        st.info(os_info[os_type])
    
    st.markdown("---")
    
    # Analysis options
    st.subheader("3. Analysis Options")
    
    col3, col4, col5 = st.columns(3)
    
    with col3:
        extract_processes = st.checkbox("Extract Processes", value=True)
        extract_network = st.checkbox("Extract Network Connections", value=True)
    
    with col4:
        extract_files = st.checkbox("Extract File Handles", value=True)
        extract_registry = st.checkbox("Extract Registry (Windows)", value=(os_type == "Windows"))
    
    with col5:
        extract_modules = st.checkbox("Extract Loaded Modules", value=True)
        extract_secrets = st.checkbox("Scan for Secrets", value=False)
    
    st.markdown("---")
    
    # Start Analysis button
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
            if uploaded_file is None:
                st.error("⚠️ Please upload a snapshot file first!")
            elif not BACKEND_AVAILABLE:
                st.error("⚠️ VAST backend not configured. Please ensure all VAST scripts are in the same directory.")
            elif uploaded_file.size > (4096 * 1024 * 1024):  # 4GB in bytes
                st.error("⚠️ File exceeds 4GB limit. Please use a smaller snapshot file.")
            else:
                # Save uploaded file temporarily
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
                        
                        # Prepare extraction options
                        options = {
                            "extract_processes": extract_processes,
                            "extract_network": extract_network,
                            "extract_files": extract_files,
                            "extract_registry": extract_registry and (os_type == "Windows"),
                            "extract_modules": extract_modules,
                            "extract_secrets": extract_secrets,
                        }
                        
                        # Run the actual VAST analysis
                        backend_results = run_analysis(
                            snapshot_path=tmp_path,
                            os_type=os_type.lower(),
                            options=options,
                            progress_callback=update_progress
                        )
                        
                        st.session_state.backend_results = backend_results
                        
                        # Load the results for display
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
                            
                            # Show warnings if any
                            if backend_results.get("warnings"):
                                with st.expander("⚠️ Warnings"):
                                    for warning in backend_results["warnings"]:
                                        st.warning(warning)
                        else:
                            st.error("❌ Analysis failed. Check errors below:")
                            for error in backend_results.get("errors", ["Unknown error"]):
                                st.error(error)
                
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())
                
                finally:
                    # Clean up temp file
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
    
    with col_btn2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.uploaded_file = None
            st.session_state.analysis_results = None
            st.rerun()

# Tab 2: Timeline of Events
with tab2:
    st.header("Timeline of Events")
    
    if st.session_state.analysis_results is None:
        st.info("👈 Please upload and analyze a snapshot file in the 'Upload Snapshot' tab first.")
    else:
        results = st.session_state.analysis_results
        
        # Show session directory if available
        if st.session_state.session_dir:
            st.info(f"📁 Session Directory: `{st.session_state.session_dir}`")
        
        # Summary metrics
        st.subheader("📈 Analysis Summary")
        
        summary = results.get("summary", {})
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Processes", summary.get("total_processes", len(results.get('processes', []))))
        with col2:
            st.metric("Network Connections", summary.get("total_connections", len(results.get('connections', []))))
        with col3:
            st.metric("File Objects", summary.get("total_file_objects", len(results.get('file_objects', []))))
        with col4:
            st.metric("Total Artifacts", summary.get("total_artifacts", 0))
        
        st.markdown("---")
        
        # Process visualization if we have process data
        if results.get("processes"):
            st.subheader("📊 Process Analysis")
            
            processes_df = pd.DataFrame(results["processes"])
            
            # Show process tree or list
            st.dataframe(
                processes_df,
                use_container_width=True,
                hide_index=True
            )
            
            # Add suspicious process detection if available
            if "suspicious_score" in processes_df.columns:
                suspicious = processes_df[processes_df["suspicious_score"] > 0]
                if not suspicious.empty:
                    st.warning(f"⚠️ Found {len(suspicious)} suspicious processes!")
                    st.dataframe(
                        suspicious.sort_values("suspicious_score", ascending=False),
                        use_container_width=True,
                        hide_index=True
                    )
        
        st.markdown("---")
        
        # Network connections visualization
        if results.get("connections"):
            st.subheader("🌐 Network Connections")
            
            connections_df = pd.DataFrame(results["connections"])
            
            # Filter controls
            col1, col2 = st.columns(2)
            with col1:
                show_established = st.checkbox("Show ESTABLISHED only", value=False)
            with col2:
                show_external = st.checkbox("Show external connections only", value=False)
            
            filtered_df = connections_df.copy()
            if show_established:
                filtered_df = filtered_df[filtered_df.get("State", "").str.upper() == "ESTABLISHED"]
            if show_external:
                filtered_df = filtered_df[filtered_df.get("ForeignAddr", "").str.startswith("192.168.") == False]
            
            st.dataframe(
                filtered_df,
                use_container_width=True,
                hide_index=True
            )
            
            # Show suspicious connections if available
            if "suspicious_score" in connections_df.columns:
                suspicious = connections_df[connections_df["suspicious_score"] > 0]
                if not suspicious.empty:
                    st.warning(f"⚠️ Found {len(suspicious)} suspicious connections!")
                    st.dataframe(
                        suspicious.sort_values("suspicious_score", ascending=False),
                        use_container_width=True,
                        hide_index=True
                    )
        
        st.markdown("---")
        
        # Detailed artifact tables
        st.subheader("📋 Detailed Artifacts")
        
        # Create sub-tabs for different artifact types
        available_tabs = []
        if results.get("processes"):
            available_tabs.append("Processes")
        if results.get("connections"):
            available_tabs.append("Network")
        if results.get("file_objects"):
            available_tabs.append("File Objects")
        if results.get("file_handles"):
            available_tabs.append("File Handles")
        if results.get("registry_activity"):
            available_tabs.append("Registry")
        
        if not available_tabs:
            st.info("No artifacts extracted yet.")
        else:
            artifact_tabs = st.tabs(available_tabs)
            tab_idx = 0
            
            if "Processes" in available_tabs:
                with artifact_tabs[tab_idx]:
                    processes_df = pd.DataFrame(results["processes"])
                    st.dataframe(
                        processes_df,
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    # Download button
                    csv = processes_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Processes as CSV",
                        data=csv,
                        file_name="processes.csv",
                        mime="text/csv"
                    )
                tab_idx += 1
            
            if "Network" in available_tabs:
                with artifact_tabs[tab_idx]:
                    connections_df = pd.DataFrame(results["connections"])
                    st.dataframe(
                        connections_df,
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    csv = connections_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Network Connections as CSV",
                        data=csv,
                        file_name="network.csv",
                        mime="text/csv"
                    )
                tab_idx += 1
            
            if "File Objects" in available_tabs:
                with artifact_tabs[tab_idx]:
                    file_objects_df = pd.DataFrame(results["file_objects"])
                    st.dataframe(
                        file_objects_df,
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    csv = file_objects_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download File Objects as CSV",
                        data=csv,
                        file_name="file_objects.csv",
                        mime="text/csv"
                    )
                tab_idx += 1
            
            if "File Handles" in available_tabs:
                with artifact_tabs[tab_idx]:
                    file_handles_df = pd.DataFrame(results["file_handles"])
                    st.dataframe(
                        file_handles_df,
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    csv = file_handles_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download File Handles as CSV",
                        data=csv,
                        file_name="file_handles.csv",
                        mime="text/csv"
                    )
                tab_idx += 1
            
            if "Registry" in available_tabs:
                with artifact_tabs[tab_idx]:
                    st.json(results["registry_activity"])
                    
                    # Download as JSON
                    json_str = json.dumps(results["registry_activity"], indent=2)
                    st.download_button(
                        label="📥 Download Registry Data as JSON",
                        data=json_str,
                        file_name="registry_activity.json",
                        mime="application/json"
                    )
                tab_idx += 1
            
            # Export full report
            st.markdown("---")
            col1, col2 = st.columns([1, 3])
            with col1:
                if st.button("📄 Generate Full Report"):
                    report = generate_json_report(results)
                    st.download_button(
                        label="📥 Download JSON Report",
                        data=report,
                        file_name=f"vast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )

# Helper functions
def generate_json_report(results):
    """Generate a JSON report of all findings"""
    report = {
        'metadata': {
            'analysis_date': datetime.now().isoformat(),
            'tool': 'VAST',
            'version': '1.0.0',
            'os_type': st.session_state.os_type,
            'session_dir': st.session_state.session_dir
        },
        'summary': results.get('summary', {}),
        'artifacts': {
            'processes': results.get('processes', []),
            'connections': results.get('connections', []),
            'file_objects': results.get('file_objects', []),
            'file_handles': results.get('file_handles', []),
            'registry_activity': results.get('registry_activity', {})
        }
    }
    
    return json.dumps(report, indent=2)

# Sidebar
with st.sidebar:
    st.image("https://via.placeholder.com/150x50/2c3e50/ffffff?text=VAST", use_container_width=True)
    st.markdown("### About VAST")
    st.markdown("""
    **Volatile Artifact Snapshot Triage** is a digital forensic tool for analyzing 
    VM snapshots and extracting volatile artifacts.
    
    **Supported Formats:**
    - VMware (.vmsn, .vmem)
    - VirtualBox (.sav)
    
    **Features:**
    - Direct snapshot parsing
    - Automated artifact extraction
    - Timeline visualization
    - JSON report generation
    """)
    
    st.markdown("---")
    st.markdown("### Quick Guide")
    st.markdown("""
    1. Upload your VM snapshot file
    2. Select the guest OS type
    3. Choose analysis options
    4. Click 'Start Analysis'
    5. View results in Timeline tab
    """)
    
    st.markdown("---")
    st.markdown("**ICT3215 Digital Forensics**")
    st.markdown("Group 16 - SIT 2024")