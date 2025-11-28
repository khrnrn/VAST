#!/usr/bin/env python3
"""
evaluation/run_evaluation.py

VAST Evaluation Testing Framework
Separate from production code - used for academic evaluation and benchmarking
"""

import json
import time
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add parent directory to path to import VAST modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("WARNING: psutil not installed. System metrics will be limited.")
    print("Install with: pip install psutil")


class VASTEvaluationFramework:
    """
    Academic evaluation framework for VAST project.
    Used to collect metrics for the project report, NOT for production use.
    """
    
    def __init__(self, vast_root: str = None):
        """
        Initialize evaluation framework.
        
        Args:
            vast_root: Path to VAST project root (parent of evaluation/)
        """
        if vast_root:
            self.vast_root = Path(vast_root)
        else:
            # Assume we're in evaluation/ subdirectory
            self.vast_root = Path(__file__).parent.parent
        
        self.eval_dir = Path(__file__).parent
        self.results_dir = self.eval_dir / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Check VAST components exist
        self.validate_environment()
        
        self.results = {
            "evaluation_metadata": {
                "timestamp": datetime.now().isoformat(),
                "vast_root": str(self.vast_root),
                "python_version": sys.version,
            },
            "system_specs": {},
            "test_cases": [],
            "summary": {}
        }
    
    def validate_environment(self):
        """Check that required VAST components exist"""
        required_files = [
            "parser.py",
            "memory_extractor.py", 
            "file_extractor.py",
            "artifact_enhancer.py"
        ]
        
        missing = []
        for file in required_files:
            if not (self.vast_root / file).exists():
                missing.append(file)
        
        if missing:
            print(f"ERROR: Missing VAST components: {missing}")
            print(f"Make sure you're running from evaluation/ directory")
            print(f"VAST root detected as: {self.vast_root}")
            sys.exit(1)
    
    def collect_system_info(self):
        """Collect system specifications for report"""
        print("Collecting system specifications...")
        
        specs = {
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
        }
        
        if PSUTIL_AVAILABLE:
            specs.update({
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "ram_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            })
            
            # Try to get CPU info (platform-specific)
            try:
                if hasattr(psutil, 'cpu_freq'):
                    freq = psutil.cpu_freq()
                    if freq:
                        specs["cpu_freq_ghz"] = round(freq.current / 1000, 2)
            except:
                pass
        
        self.results["system_specs"] = specs
        
        print("\nSystem Specifications:")
        print(f"  Python: {specs['python_version']}")
        print(f"  Platform: {specs['platform']}")
        if PSUTIL_AVAILABLE:
            print(f"  CPU Cores: {specs.get('cpu_count_physical', 'N/A')} physical, "
                  f"{specs.get('cpu_count_logical', 'N/A')} logical")
            print(f"  RAM: {specs.get('ram_total_gb', 'N/A')} GB total")
        print()
        
        return specs
    
    def test_snapshot_parsing(self, snapshot_path: str, test_name: str = None) -> Dict[str, Any]:
        """
        Test snapshot parsing performance
        
        Args:
            snapshot_path: Path to VM snapshot file
            test_name: Optional name for this test case
        
        Returns:
            Dictionary with test results
        """
        print(f"\n{'='*70}")
        print(f"TEST: Snapshot Parsing - {test_name or snapshot_path}")
        print(f"{'='*70}")
        
        snapshot_file = Path(snapshot_path)
        
        if not snapshot_file.exists():
            print(f"ERROR: Snapshot not found: {snapshot_path}")
            return {"error": "File not found", "snapshot": str(snapshot_path)}
        
        # Get file info
        file_size_bytes = snapshot_file.stat().st_size
        file_size_gb = file_size_bytes / (1024**3)
        file_format = snapshot_file.suffix
        
        print(f"Snapshot: {snapshot_file.name}")
        print(f"Size: {file_size_gb:.2f} GB")
        print(f"Format: {file_format}")
        
        # Create test session directory
        test_session = self.results_dir / f"test_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Time the parsing
        start_time = time.time()
        start_mem = None
        if PSUTIL_AVAILABLE:
            start_mem = psutil.Process().memory_info().rss / (1024**2)  # MB
        
        try:
            # Run parser
            result = subprocess.run(
                [sys.executable, str(self.vast_root / "parser.py"), 
                 str(snapshot_path), "--session", str(test_session)],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(self.vast_root)
            )
            
            end_time = time.time()
            parse_duration = end_time - start_time
            
            end_mem = None
            mem_delta = None
            if PSUTIL_AVAILABLE and start_mem:
                end_mem = psutil.Process().memory_info().rss / (1024**2)
                mem_delta = end_mem - start_mem
            
            success = result.returncode == 0
            
            # Check for output file
            raw_files = list((test_session / "raw").glob("*.raw")) if test_session.exists() else []
            output_exists = len(raw_files) > 0
            
            test_result = {
                "test_name": test_name or snapshot_file.name,
                "snapshot_path": str(snapshot_path),
                "file_size_gb": round(file_size_gb, 2),
                "file_format": file_format,
                "parse_duration_seconds": round(parse_duration, 2),
                "memory_delta_mb": round(mem_delta, 2) if mem_delta else None,
                "success": success,
                "output_generated": output_exists,
                "test_session": str(test_session),
                "warnings": []
            }
            
            # Check for warnings in output
            if "warning" in result.stdout.lower() or "warning" in result.stderr.lower():
                test_result["warnings"].append("Parser generated warnings - check output")
            
            print(f"\nResults:")
            print(f"  Duration: {parse_duration:.2f} seconds")
            if mem_delta:
                print(f"  Memory used: {mem_delta:.2f} MB")
            print(f"  Success: {success}")
            print(f"  Output generated: {output_exists}")
            
            if not success:
                print(f"\nSTDERR: {result.stderr[:500]}")
                test_result["error_output"] = result.stderr[:500]
            
            return test_result
            
        except subprocess.TimeoutExpired:
            print("ERROR: Parsing timed out after 600 seconds")
            return {
                "test_name": test_name or snapshot_file.name,
                "snapshot_path": str(snapshot_path),
                "file_size_gb": round(file_size_gb, 2),
                "error": "Timeout after 600 seconds"
            }
        except Exception as e:
            print(f"ERROR: {str(e)}")
            return {
                "test_name": test_name or snapshot_file.name,
                "snapshot_path": str(snapshot_path),
                "error": str(e)
            }
    
    def test_end_to_end(self, snapshot_path: str, os_type: str = "windows", 
                        test_name: str = None) -> Dict[str, Any]:
        """
        Test complete VAST pipeline end-to-end
        
        Args:
            snapshot_path: Path to VM snapshot
            os_type: Guest OS type (windows/linux)
            test_name: Optional name for this test
        
        Returns:
            Dictionary with comprehensive test results
        """
        print(f"\n{'='*70}")
        print(f"TEST: End-to-End Analysis - {test_name or snapshot_path}")
        print(f"{'='*70}")
        
        test_session = self.results_dir / f"e2e_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        snapshot_file = Path(snapshot_path)
        file_size_gb = snapshot_file.stat().st_size / (1024**3)
        
        print(f"Snapshot: {snapshot_file.name}")
        print(f"Size: {file_size_gb:.2f} GB")
        print(f"OS Type: {os_type}")
        
        # Track overall time
        overall_start = time.time()
        stage_times = {}
        
        try:
            # Stage 1: Parsing
            print("\n[1/5] Parsing snapshot...")
            stage_start = time.time()
            parse_result = subprocess.run(
                [sys.executable, str(self.vast_root / "parser.py"),
                 str(snapshot_path), "--session", str(test_session)],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(self.vast_root)
            )
            stage_times["parsing"] = time.time() - stage_start
            print(f"  Completed in {stage_times['parsing']:.2f}s")
            
            if parse_result.returncode != 0:
                return {
                    "test_name": test_name,
                    "error": "Parsing failed",
                    "stage_times": stage_times
                }
            
            # Find raw memory file
            raw_files = list((test_session / "raw").glob("*.raw"))
            if not raw_files:
                return {"test_name": test_name, "error": "No raw memory file generated"}
            
            raw_memory = str(raw_files[0])
            
            # Stage 2: Memory extraction
            print("\n[2/5] Extracting memory artifacts...")
            stage_start = time.time()
            mem_result = subprocess.run(
                [sys.executable, str(self.vast_root / "memory_extractor.py"),
                 raw_memory, "--os", os_type, "--session", str(test_session)],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(self.vast_root)
            )
            stage_times["memory_extraction"] = time.time() - stage_start
            print(f"  Completed in {stage_times['memory_extraction']:.2f}s")
            
            # Stage 3: File extraction
            print("\n[3/5] Extracting file artifacts...")
            stage_start = time.time()
            file_result = subprocess.run(
                [sys.executable, str(self.vast_root / "file_extractor.py"),
                 raw_memory, "--os", os_type, "--session", str(test_session)],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(self.vast_root)
            )
            stage_times["file_extraction"] = time.time() - stage_start
            print(f"  Completed in {stage_times['file_extraction']:.2f}s")
            
            # Find extraction outputs
            memory_jsons = list((test_session / "extracted_memory").glob("*_memory.json"))
            file_jsons = list((test_session / "extracted_files").glob("*_file_activity.json"))
            
            if not memory_jsons:
                return {
                    "test_name": test_name,
                    "error": "Memory extraction produced no output",
                    "stage_times": stage_times
                }
            
            memory_json = str(memory_jsons[0])
            
            # Stage 4: Enhancement
            print("\n[4/5] Enhancing artifacts...")
            stage_start = time.time()
            enhance_result = subprocess.run(
                [sys.executable, str(self.vast_root / "artifact_enhancer.py"),
                 memory_json, "--session", str(test_session)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.vast_root)
            )
            stage_times["enhancement"] = time.time() - stage_start
            print(f"  Completed in {stage_times['enhancement']:.2f}s")
            
            # Stage 5: Automated analysis (if file extraction succeeded)
            if file_jsons:
                print("\n[5/5] Running automated analysis...")
                file_json = str(file_jsons[0])
                stage_start = time.time()
                analysis_result = subprocess.run(
                    [sys.executable, str(self.vast_root / "automated_analysis.py"),
                     raw_memory, memory_json, file_json, "--session", str(test_session)],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=str(self.vast_root)
                )
                stage_times["automated_analysis"] = time.time() - stage_start
                print(f"  Completed in {stage_times['automated_analysis']:.2f}s")
            
            # Calculate totals
            total_time = time.time() - overall_start
            
            # Load and count artifacts
            with open(memory_json) as f:
                mem_data = json.load(f)
            
            artifact_counts = {
                "processes": len(mem_data.get("processes", [])),
                "connections": len(mem_data.get("connections", [])),
                "files": 0
            }
            
            if file_jsons:
                with open(file_json) as f:
                    file_data = json.load(f)
                artifact_counts["files"] = len(file_data.get("file_objects", []))
            
            # Calculate percentages
            stage_percentages = {
                stage: round((duration / total_time) * 100, 1)
                for stage, duration in stage_times.items()
            }
            
            result = {
                "test_name": test_name or snapshot_file.name,
                "snapshot_path": str(snapshot_path),
                "file_size_gb": round(file_size_gb, 2),
                "os_type": os_type,
                "total_duration_seconds": round(total_time, 2),
                "total_duration_minutes": round(total_time / 60, 2),
                "stage_times_seconds": {k: round(v, 2) for k, v in stage_times.items()},
                "stage_percentages": stage_percentages,
                "artifact_counts": artifact_counts,
                "test_session": str(test_session),
                "success": True
            }
            
            print(f"\n{'='*70}")
            print(f"RESULTS:")
            print(f"  Total Time: {result['total_duration_minutes']:.2f} minutes")
            print(f"  Artifacts Found:")
            print(f"    Processes: {artifact_counts['processes']}")
            print(f"    Connections: {artifact_counts['connections']}")
            print(f"    Files: {artifact_counts['files']}")
            print(f"  Stage Breakdown:")
            for stage, pct in stage_percentages.items():
                print(f"    {stage}: {pct}%")
            print(f"{'='*70}")
            
            return result
            
        except Exception as e:
            return {
                "test_name": test_name,
                "error": str(e),
                "stage_times": stage_times
            }
    
    def save_results(self):
        """Save evaluation results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.results_dir / f"evaluation_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nEvaluation results saved to: {report_file}")
        
        # Also generate a summary
        summary_file = self.results_dir / f"evaluation_summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("VAST EVALUATION SUMMARY\n")
            f.write("="*70 + "\n\n")
            
            f.write("SYSTEM SPECIFICATIONS\n")
            f.write("-"*70 + "\n")
            for key, value in self.results["system_specs"].items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            
            f.write("TEST CASES\n")
            f.write("-"*70 + "\n")
            for i, test in enumerate(self.results["test_cases"], 1):
                f.write(f"\nTest {i}: {test.get('test_name', 'Unnamed')}\n")
                if "total_duration_minutes" in test:
                    f.write(f"  Duration: {test['total_duration_minutes']:.2f} minutes\n")
                if "artifact_counts" in test:
                    f.write(f"  Artifacts: {test['artifact_counts']}\n")
                if "error" in test:
                    f.write(f"  ERROR: {test['error']}\n")
        
        print(f"Summary saved to: {summary_file}")
        
        return report_file


def main():
    """Main evaluation routine"""
    print("="*70)
    print("VAST ACADEMIC EVALUATION FRAMEWORK")
    print("="*70)
    print()
    
    # Initialize framework
    framework = VASTEvaluationFramework()
    
    # Collect system info
    framework.collect_system_info()
    
    # Define test cases
    # TODO: Replace with your actual snapshot paths
    test_cases = [
        {
            "name": "Baseline 1GB Windows 10",
            "path": "path/to/baseline_1gb.vmem",
            "os": "windows",
            "description": "Clean Windows 10 installation"
        },
        # Add more test cases here
    ]
    
    if not any(Path(tc["path"]).exists() for tc in test_cases):
        print("="*70)
        print("NO TEST SNAPSHOTS CONFIGURED")
        print("="*70)
        print("\nPlease edit evaluation/run_evaluation.py and add your snapshot paths")
        print("\nExample configuration:")
        print("""
        test_cases = [
            {
                "name": "Clean Windows 10 - 4GB",
                "path": "../test_snapshots/windows10_clean.vmem",
                "os": "windows",
                "description": "Baseline system"
            },
            {
                "name": "Suspicious Activity - 4GB",
                "path": "../test_snapshots/windows10_suspicious.vmem",
                "os": "windows",
                "description": "System with simulated malware"
            },
        ]
        """)
        return 1
    
    # Run tests
    for test_case in test_cases:
        if not Path(test_case["path"]).exists():
            print(f"Skipping {test_case['name']} - file not found")
            continue
        
        # Run end-to-end test
        result = framework.test_end_to_end(
            snapshot_path=test_case["path"],
            os_type=test_case["os"],
            test_name=test_case["name"]
        )
        
        framework.results["test_cases"].append(result)
    
    # Save results
    framework.save_results()
    
    print("\n" + "="*70)
    print("EVALUATION COMPLETE")
    print("="*70)
    print("\nNext steps:")
    print("1. Review evaluation_results/ directory")
    print("2. Use data to fill in report placeholders")
    print("3. Compare with manual Volatility workflow for accuracy")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())