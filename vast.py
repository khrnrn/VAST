#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


def run_command(cmd: list, description: str) -> bool:
    """Run a command and report success/failure."""
    print(f"\n{'=' * 60}")
    print(f"[VAST] {description}")
    print(f"{'=' * 60}")
    print(f"Running: {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, check=True, capture_output=False, text=True)
        print(f"SUCCESS: {description} completed successfully\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {description} failed with error code {e.returncode}\n")
        return False
    except Exception as e:
        print(f"ERROR: {description} failed: {e}\n")
        return False


def get_latest_file(pattern: str) -> Optional[Path]:
    """Get the most recent file matching a glob pattern."""
    files = list(Path(".").glob(pattern))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def main():
    parser = argparse.ArgumentParser(
        description="VAST - Volatile Artifact Snapshot Triage: Full pipeline orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
                Examples:
              # Run full pipeline on VMware snapshot
              python vast.py --input test.vmem --os windows

              # Run with baseline comparison
              python vast.py --input test.vmem --baseline baseline_memory.json

              # Skip enhancement phase
              python vast.py --input test.vmem --skip-enhance
        """
    )
    parser.add_argument("--input", required=True, help="Path to VM snapshot (.vmem, .sav, .vmsn)")
    parser.add_argument("--os", default="windows", help="Guest OS type (default: windows)")
    parser.add_argument("--output", help="Optional: Final report output path")
    parser.add_argument("--baseline", help="Optional: Baseline memory extraction JSON")
    parser.add_argument("--ioc", help="Optional: IOC configuration JSON")
    parser.add_argument("--skip-enhance", action="store_true", help="Skip the enhancement/analysis phase")

    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}")
        return 1

    # Handle .vmsn by finding associated .vmem
    snapshot_files = [input_path]
    if input_path.suffix.lower() == ".vmsn":
        vmem_path = input_path.with_suffix(".vmem")
        if not vmem_path.exists():
            print(f"ERROR: Paired .vmem file not found: {vmem_path}")
            return 1
        print(f"[VAST] Detected VMware snapshot pair: {input_path} + {vmem_path}")
        snapshot_files = [input_path, vmem_path]

    # Create timestamped session directory
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = Path("output") / timestamp

    for sub in ["raw", "extracted_memory", "extracted_files", "enhanced", "reports"]:
        (session_dir / sub).mkdir(parents=True, exist_ok=True)

    print(f"[VAST] Session directory: {session_dir}")

    print("\n" + "=" * 60)
    print("VAST - Volatile Artifact Snapshot Triage")
    print("=" * 60)
    print(f"Input snapshot: {input_path}")
    print(f"OS Type: {args.os}")
    print("=" * 60)

    # Step 1: Parse snapshot (pass all snapshot files)
    parser_cmd = [sys.executable, "parser.py"]
    for f in snapshot_files:
        parser_cmd.append(str(f))
    parser_cmd.extend(["--session", str(session_dir)])

    if not run_command(parser_cmd, "Step 1/6: Parsing VM snapshot"):
        return 1

    # Find the generated raw file
    # Look for any supported raw memory file (preserve original extension)
    raw_file = (
            get_latest_file(f"{session_dir}/raw/snapshot_*.vmem") or
            get_latest_file(f"{session_dir}/raw/snapshot_*.raw") or
            get_latest_file(f"{session_dir}/raw/snapshot_*.sav")
    )
    if not raw_file:
        print("ERROR: Could not find generated raw memory file")
        return 1
    print(f"Raw memory dump: {raw_file}\n")

    # Step 2: Extract memory artifacts
    if not run_command(
            [
                sys.executable, "memory_extractor.py",
                str(raw_file),
                "--os", args.os,
                "--session", str(session_dir)
            ],
            "Step 2/6: Extracting memory artifacts (processes, network)"
    ):
        return 1

    memory_json = get_latest_file(f"{session_dir}/extracted_memory/*_memory.json")
    if not memory_json:
        print("ERROR: Could not find memory extraction JSON")
        return 1
    print(f"Memory artifacts: {memory_json}\n")

    # Step 3: Extract file/activity artifacts
    if not run_command(
            [
                sys.executable, "file_extractor.py",
                str(raw_file),
                "--os", args.os,
                "--session", str(session_dir)
            ],
            "Step 3/6: Extracting file/activity artifacts"
    ):
        return 1

    file_json = get_latest_file(f"{session_dir}/extracted_files/*_file_activity.json")
    if not file_json:
        print("ERROR: Could not find file extraction JSON")
        return 1
    print(f"File artifacts: {file_json}\n")

    # Step 4: Enhancement
    memory_enhanced = None
    file_enhanced = None

    if not args.skip_enhance:
        # Enhance memory
        enhance_cmd = [
            sys.executable, "artifact_enhancer.py",
            str(memory_json),
            "--session", str(session_dir)
        ]
        if args.baseline:
            enhance_cmd.extend(["--baseline", args.baseline])
        if args.ioc:
            enhance_cmd.extend(["--ioc", args.ioc])

        if run_command(enhance_cmd, "Step 4a/6: Enhancing memory artifacts"):
            memory_enhanced = get_latest_file(f"{session_dir}/enhanced/*_memory_enriched.json")

        # Enhance files
        enhance_cmd = [
            sys.executable, "artifact_enhancer.py",
            str(file_json),
            "--session", str(session_dir)
        ]
        if args.baseline:
            enhance_cmd.extend(["--baseline", args.baseline])
        if args.ioc:
            enhance_cmd.extend(["--ioc", args.ioc])

        if run_command(enhance_cmd, "Step 4b/6: Enhancing file artifacts"):
            file_enhanced = get_latest_file(f"{session_dir}/enhanced/*_file_activity_enriched.json")

    # Step 5: Generate report
    report = {
        "vast_version": "1.0",
        "input_snapshot": str(input_path),
        "os_type": args.os,
        "extraction_files": {
            "raw_memory": str(raw_file),
            "memory_artifacts": str(memory_json),
            "file_artifacts": str(file_json),
        },
        "summary": {}
    }

    if memory_enhanced:
        report["extraction_files"]["memory_enhanced"] = str(memory_enhanced)
    if file_enhanced:
        report["extraction_files"]["file_enhanced"] = str(file_enhanced)

    # Load artifact counts
    try:
        with open(memory_json) as f:
            memory_data = json.load(f)
            report["summary"]["processes_found"] = len(memory_data.get("processes", []))
            report["summary"]["connections_found"] = len(memory_data.get("connections", []))
            if memory_enhanced:
                with open(memory_enhanced) as fe:
                    enhanced_data = json.load(fe)
                    suspicious_procs = [p for p in enhanced_data.get("processes", []) if
                                        p.get("suspicious_score", 0) > 0]
                    suspicious_conns = [c for c in enhanced_data.get("connections", []) if
                                        c.get("suspicious_score", 0) > 0]
                    report["summary"]["suspicious_processes"] = len(suspicious_procs)
                    report["summary"]["suspicious_connections"] = len(suspicious_conns)
    except Exception as e:
        print(f"WARNING: Could not load memory data: {e}")

    try:
        with open(file_json) as f:
            file_data = json.load(f)
            report["summary"]["file_objects_found"] = len(file_data.get("file_objects", []))
            report["summary"]["file_handles_found"] = len(file_data.get("file_handles", []))
            report["summary"]["registry_hives_found"] = len(file_data.get("registry_activity", {}).get("hives", []))
    except Exception as e:
        print(f"WARNING: Could not load file data: {e}")

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = session_dir / "reports" / f"vast_report_{timestamp}.json"

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"SUCCESS: Final report written to: {output_path}\n")

    # Step 6: Automated Deep Analysis
    automated_cmd = [
        sys.executable, "automated_analysis.py",
        str(raw_file),
        str(memory_enhanced if memory_enhanced else memory_json),
        str(file_enhanced if file_enhanced else file_json),
        "--session", str(session_dir)
    ]

    if not run_command(automated_cmd, "Step 6/6: Automated Deep Forensic Analysis"):
        print("WARNING: Automated analysis failed, continuing...\n")
    else:
        print("Automated analysis completed successfully.\n")

    # Final summary
    print("\n" + "=" * 60)
    print("VAST EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Snapshot parsed: {input_path.name}")
    print(f"Raw memory: {raw_file.name}")
    print(f"Memory artifacts: {memory_json.name}")
    print(f"File artifacts: {file_json.name}")
    if not args.skip_enhance:
        if memory_enhanced:
            print(f"Memory enhanced: {memory_enhanced.name}")
        if file_enhanced:
            print(f"File enhanced: {file_enhanced.name}")
    print(f"Final report: {output_path.name}")

    if report.get("summary"):
        print("\nArtifact Counts:")
        for key, value in report["summary"].items():
            print(f"   - {key.replace('_', ' ').title()}: {value}")

    print("=" * 60)
    print("\nVAST pipeline completed successfully!")
    print(f"\nView results:")
    print(f"   - Memory: {memory_json}")
    print(f"   - Files: {file_json}")
    if memory_enhanced:
        print(f"   - Enhanced Memory: {memory_enhanced}")
    if file_enhanced:
        print(f"   - Enhanced Files: {file_enhanced}")
    print(f"   - Report: {output_path}")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())