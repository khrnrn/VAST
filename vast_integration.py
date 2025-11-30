#!/usr/bin/env python3
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Callable
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VASTAnalyzer:
    """
    High-level interface to run VAST analysis pipeline from the dashboard.
    """
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize the VAST analyzer.
        
        Args:
            base_dir: Base directory where VAST scripts are located. 
                     Defaults to current directory.
        """
        self.base_dir = base_dir or Path.cwd()
        self.session_dir: Optional[Path] = None
        self.progress_callback: Optional[Callable] = None
        
    def set_progress_callback(self, callback: Callable[[str, float], None]):
        """
        Set a callback function for progress updates.
        
        Args:
            callback: Function that takes (status_message: str, progress: float)
        """
        self.progress_callback = callback
    
    def _update_progress(self, message: str, progress: float):
        """Internal method to update progress."""
        if self.progress_callback:
            self.progress_callback(message, progress)
        logger.info(f"[{progress*100:.0f}%] {message}")
    
    def _run_script(self, script_name: str, args: list) -> tuple[bool, str]:
        """
        Run a VAST Python script and capture output.
        
        Args:
            script_name: Name of the script (e.g., 'parser.py')
            args: List of command-line arguments
            
        Returns:
            Tuple of (success: bool, output: str)
        """
        script_path = self.base_dir / script_name
        
        if not script_path.exists():
            return False, f"Script not found: {script_path}"
        
        cmd = [sys.executable, str(script_path)] + args
        
        try:
            # For large Linux dumps, this can take 30+ minutes
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=None  # NO TIMEOUT - allow unlimited time for large dumps
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr or result.stdout
                
        except subprocess.TimeoutExpired:
            return False, "Operation timed out"
        except Exception as e:
            return False, str(e)
    
    def analyze_snapshot(
        self,
        snapshot_files,  # List of Path objects or single Path
        os_type: str = "windows",
        extract_processes: bool = True,
        extract_network: bool = True,
        extract_files: bool = True,
        extract_registry: bool = False,
        extract_modules: bool = False,
        extract_secrets: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the full VAST analysis pipeline on snapshot file(s).
        
        Args:
            snapshot_files: Path object(s) to VM snapshot file(s) - for Linux, include both .vmem and .vmsn
            os_type: Operating system type ('windows', 'linux', or 'macos')
            extract_*: Flags for what artifacts to extract
            
        Returns:
            Dictionary containing analysis results and file paths
        """
        # Convert to list if single file
        if isinstance(snapshot_files, Path):
            file_list = [snapshot_files]
        else:
            file_list = list(snapshot_files)
        
        results = {
            "success": False,
            "session_dir": None,
            "raw_memory": None,
            "memory_json": None,
            "file_json": None,
            "memory_enhanced": None,
            "file_enhanced": None,
            "report_json": None,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Create session directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_dir = self.base_dir / "output" / timestamp
            
            # Create subdirectories
            (self.session_dir / "raw").mkdir(parents=True, exist_ok=True)
            (self.session_dir / "extracted_memory").mkdir(parents=True, exist_ok=True)
            (self.session_dir / "extracted_files").mkdir(parents=True, exist_ok=True)
            (self.session_dir / "enhanced").mkdir(parents=True, exist_ok=True)
            (self.session_dir / "reports").mkdir(parents=True, exist_ok=True)
            
            results["session_dir"] = str(self.session_dir)
            
            # Step 1: Parse snapshot
            self._update_progress("Parsing VM snapshot file...", 0.0)
            
            # Pass ALL files to parser
            parser_args = []
            for f in file_list:
                parser_args.append(str(f))
            parser_args.extend(["--session", str(self.session_dir)])
            
            success, output = self._run_script("parser.py", parser_args)
            
            if not success:
                results["errors"].append(f"Snapshot parsing failed: {output}")
                return results
            
            self._update_progress("Snapshot parsed successfully", 0.14)
            
            # Find the raw memory file (check for .vmem, .raw, .sav)
            raw_files = (
                list((self.session_dir / "raw").glob("snapshot_*.vmem")) +
                list((self.session_dir / "raw").glob("snapshot_*.raw")) +
                list((self.session_dir / "raw").glob("snapshot_*.sav"))
            )
            if not raw_files:
                results["errors"].append("No raw memory file generated (.vmem, .raw, or .sav)")
                return results
            
            raw_memory = max(raw_files, key=lambda p: p.stat().st_mtime)
            results["raw_memory"] = str(raw_memory)
            
            # Step 2: Extract memory artifacts
            if extract_processes or extract_network:
                self._update_progress("Extracting memory artifacts (processes, network)... This may take 10-30 minutes for large dumps", 0.14)
                success, output = self._run_script(
                    "memory_extractor.py",
                    [
                        str(raw_memory),
                        "--os", os_type,
                        "--session", str(self.session_dir)
                    ]
                )
                
                if not success:
                    results["warnings"].append(f"Memory extraction failed: {output}")
                else:
                    self._update_progress("Memory artifacts extracted", 0.28)
                    
                    # Find memory JSON
                    memory_jsons = list((self.session_dir / "extracted_memory").glob("*_memory.json"))
                    if memory_jsons:
                        results["memory_json"] = str(max(memory_jsons, key=lambda p: p.stat().st_mtime))
            
            # Step 3: Extract file artifacts
            if extract_files or extract_registry:
                self._update_progress("Extracting file and registry artifacts... This may take 10-30 minutes", 0.28)
                success, output = self._run_script(
                    "file_extractor.py",
                    [
                        str(raw_memory),
                        "--os", os_type,
                        "--session", str(self.session_dir)
                    ]
                )
                
                if not success:
                    results["warnings"].append(f"File extraction failed: {output}")
                else:
                    self._update_progress("File artifacts extracted", 0.42)
                    
                    # Find file JSON
                    file_jsons = list((self.session_dir / "extracted_files").glob("*_file_activity.json"))
                    if file_jsons:
                        results["file_json"] = str(max(file_jsons, key=lambda p: p.stat().st_mtime))
            
            # Step 4: Enhancement phase
            if results["memory_json"]:
                self._update_progress("Enhancing artifacts with threat intelligence...", 0.42)
                success, output = self._run_script(
                    "artifact_enhancer.py",
                    [
                        results["memory_json"],
                        "--session", str(self.session_dir)
                    ]
                )
                
                if success:
                    enhanced_jsons = list((self.session_dir / "enhanced").glob("*_memory_enriched.json"))
                    if enhanced_jsons:
                        results["memory_enhanced"] = str(max(enhanced_jsons, key=lambda p: p.stat().st_mtime))
                
                self._update_progress("Memory artifacts enhanced", 0.56)
            
            if results["file_json"]:
                self._update_progress("Enhancing file artifacts...", 0.56)
                success, output = self._run_script(
                    "artifact_enhancer.py",
                    [
                        results["file_json"],
                        "--session", str(self.session_dir)
                    ]
                )
                
                if success:
                    enhanced_jsons = list((self.session_dir / "enhanced").glob("*_file_activity_enriched.json"))
                    if enhanced_jsons:
                        results["file_enhanced"] = str(max(enhanced_jsons, key=lambda p: p.stat().st_mtime))
                
                self._update_progress("File artifacts enhanced", 0.70)
            
            # Step 5: Generate final report
            self._update_progress("Generating final report...", 0.70)
            report = self._generate_report(results, file_list, os_type)
            
            report_path = self.session_dir / "reports" / f"vast_report_{timestamp}.json"
            report_path.write_text(json.dumps(report, indent=2))
            results["report_json"] = str(report_path)
            
            self._update_progress("Report generated", 0.85)
            
            # Step 6: Run automated analysis
            self._update_progress("Running automated deep analysis...", 0.85)
            
            memory_file = results["memory_enhanced"] or results["memory_json"]
            file_file = results["file_enhanced"] or results["file_json"]
            
            if memory_file and file_file:
                success, output = self._run_script(
                    "automated_analysis.py",
                    [
                        str(raw_memory),
                        memory_file,
                        file_file,
                        "--os", os_type,
                        "--session", str(self.session_dir)
                    ]
                )
                
                if not success:
                    results["warnings"].append(f"Automated analysis failed: {output}")
            
            self._update_progress("Analysis complete!", 1.0)
            results["success"] = True
            
        except Exception as e:
            results["errors"].append(f"Unexpected error: {str(e)}")
            logger.exception("Analysis failed with exception")
        
        return results
    
    def _generate_report(self, results: Dict[str, Any], snapshot_files: list, os_type: str) -> Dict[str, Any]:
        """Generate the final VAST report."""
        report = {
            "vast_version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "input_snapshots": [str(f) for f in snapshot_files],
            "os_type": os_type,
            "session_dir": results["session_dir"],
            "files": {
                "raw_memory": results.get("raw_memory"),
                "memory_artifacts": results.get("memory_json"),
                "file_artifacts": results.get("file_json"),
                "memory_enhanced": results.get("memory_enhanced"),
                "file_enhanced": results.get("file_enhanced"),
            },
            "summary": {},
            "errors": results.get("errors", []),
            "warnings": results.get("warnings", [])
        }
        
        # Load artifact counts
        if results.get("memory_json"):
            try:
                with open(results["memory_json"]) as f:
                    memory_data = json.load(f)
                    report["summary"]["processes_found"] = len(memory_data.get("processes", []))
                    report["summary"]["connections_found"] = len(memory_data.get("connections", []))
            except Exception as e:
                logger.warning(f"Could not load memory data: {e}")
        
        if results.get("file_json"):
            try:
                with open(results["file_json"]) as f:
                    file_data = json.load(f)
                    report["summary"]["file_objects_found"] = len(file_data.get("file_objects", []))
                    report["summary"]["file_handles_found"] = len(file_data.get("file_handles", []))
            except Exception as e:
                logger.warning(f"Could not load file data: {e}")
        
        # Add enhanced statistics
        if results.get("memory_enhanced"):
            try:
                with open(results["memory_enhanced"]) as f:
                    enhanced = json.load(f)
                    suspicious = [p for p in enhanced.get("processes", []) 
                                if p.get("suspicious_score", 0) > 0]
                    report["summary"]["suspicious_processes"] = len(suspicious)
            except Exception as e:
                logger.warning(f"Could not load enhanced memory data: {e}")
        
        return report
    
    def load_results(self, session_dir: Path) -> Dict[str, Any]:
        """
        Load results from a previous analysis session.
        
        Args:
            session_dir: Path to the session directory
            
        Returns:
            Dictionary containing the loaded results
        """
        results = {
            "success": False,
            "session_dir": str(session_dir),
            "processes": [],
            "connections": [],
            "file_objects": [],
            "file_handles": [],
            "registry_activity": {},
            "timeline": [],
            "summary": {}
        }
        
        try:
            # Load memory artifacts
            memory_jsons = list((session_dir / "extracted_memory").glob("*_memory.json"))
            if memory_jsons:
                memory_json = max(memory_jsons, key=lambda p: p.stat().st_mtime)
                with open(memory_json) as f:
                    memory_data = json.load(f)
                    results["processes"] = memory_data.get("processes", [])
                    results["connections"] = memory_data.get("connections", [])
            
            # Load file artifacts
            file_jsons = list((session_dir / "extracted_files").glob("*_file_activity.json"))
            if file_jsons:
                file_json = max(file_jsons, key=lambda p: p.stat().st_mtime)
                with open(file_json) as f:
                    file_data = json.load(f)
                    results["file_objects"] = file_data.get("file_objects", [])
                    results["file_handles"] = file_data.get("file_handles", [])
                    results["registry_activity"] = file_data.get("registry_activity", {})
            
            # Load enhanced data if available
            enhanced_jsons = list((session_dir / "enhanced").glob("*_memory_enriched.json"))
            if enhanced_jsons:
                enhanced_json = max(enhanced_jsons, key=lambda p: p.stat().st_mtime)
                with open(enhanced_json) as f:
                    enhanced_data = json.load(f)
                    results["processes"] = enhanced_data.get("processes", results["processes"])
                    results["connections"] = enhanced_data.get("connections", results["connections"])
            
            # Build timeline
            results["timeline"] = self._build_timeline(results)
            
            # Calculate summary
            results["summary"] = {
                "total_processes": len(results["processes"]),
                "total_connections": len(results["connections"]),
                "total_file_objects": len(results["file_objects"]),
                "total_file_handles": len(results["file_handles"]),
                "total_artifacts": (
                    len(results["processes"]) + 
                    len(results["connections"]) + 
                    len(results["file_objects"]) +
                    len(results["file_handles"])
                )
            }
            
            results["success"] = True
            
        except Exception as e:
            logger.exception("Failed to load results")
            results["errors"] = [str(e)]
        
        return results
    
    def _build_timeline(self, results: Dict[str, Any]) -> list:
        """Build a unified timeline from all artifacts."""
        events = []
        
        # Add process events (if they have timestamps)
        for proc in results.get("processes", []):
            # Most process data from Volatility doesn't have timestamps
            # We'd need to add this from CreateTime if available
            pass
        
        # Add network connection events
        for conn in results.get("connections", []):
            # Similarly, most network data doesn't have explicit timestamps
            pass
        
        # For now, return empty timeline
        # This would need enhancement based on actual data structure
        return events


# Convenience function for dashboard
def run_analysis(
    snapshot_files,
    os_type: str,
    options: Dict[str, bool],
    progress_callback: Optional[Callable] = None
) -> Dict[str, Any]:
    """
    Convenience function to run VAST analysis from dashboard.
    
    Args:
        snapshot_files: Path to snapshot file(s) - string or list of Path objects
        os_type: Operating system type
        options: Dictionary of extraction options
        progress_callback: Optional callback for progress updates
        
    Returns:
        Analysis results dictionary
    """
    analyzer = VASTAnalyzer()
    
    if progress_callback:
        analyzer.set_progress_callback(progress_callback)
    
    # Convert to list if single file
    if isinstance(snapshot_files, (str, Path)):
        files = [Path(snapshot_files)]
    else:
        files = [Path(f) for f in snapshot_files]
    
    return analyzer.analyze_snapshot(
        snapshot_files=files,
        os_type=os_type,
        extract_processes=options.get("extract_processes", True),
        extract_network=options.get("extract_network", True),
        extract_files=options.get("extract_files", True),
        extract_registry=options.get("extract_registry", False),
        extract_modules=options.get("extract_modules", False),
        extract_secrets=options.get("extract_secrets", False),
    )