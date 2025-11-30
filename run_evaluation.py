#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Optional

from vast_integration import VASTAnalyzer  # uses your existing pipeline

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_LEVEL = logging.INFO
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("run_evaluation")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def project_root() -> Path:
    """Return the directory containing this script (project root)."""
    return Path(__file__).resolve().parent


def infer_os_type(snapshot: Path) -> str:
    """
    Infer OS type from snapshot filename.

    Heuristics:
        - name contains "win"      -> windows
        - name contains "mac"      -> macos
        - name contains "ubuntu"   -> linux
        - name contains "linux"    -> linux
    """
    name = snapshot.name.lower()

    if "win" in name:
        return "windows"
    if "mac" in name or "osx" in name:
        return "macos"
    if "ubuntu" in name or "linux" in name:
        return "linux"

    raise ValueError(
        f"Could not infer OS type from filename '{snapshot.name}'. "
        "Please supply --os {windows,linux,macos} explicitly."
    )


DEFAULT_SNAPSHOT_NAMES = [
    "windows-snapshot.vmem",
    "macOS-snapshot.vmem",
    "macOS-snapshot.vmsn",
    "ubuntu-snapshot.vmem",
    "ubuntu-snapshot.vmsn",
]


def find_default_snapshot(root: Path) -> Optional[Path]:
    """
    Look for a snapshot file in the project root if --snapshot is not given.

    Returns:
        Path to the snapshot if exactly one candidate is found, otherwise None.
    """
    candidates = [root / name for name in DEFAULT_SNAPSHOT_NAMES if (root / name).exists()]

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    # More than one default present – force user to choose
    logger.warning("Multiple default snapshot files found:")
    for c in candidates:
        logger.warning("  - %s", c.name)
    logger.warning("Please specify one explicitly with --snapshot")
    return None


def build_options(os_type: str) -> Dict[str, bool]:
    """
    Build extraction options dict for VASTAnalyzer.analyze_snapshot().

    You can tweak these flags for different OSes if needed.
    """
    os_type = os_type.lower()
    return {
        "extract_processes": True,
        "extract_network": True,
        "extract_files": True,
        # Registry is mainly relevant on Windows
        "extract_registry": os_type == "windows",
        # You’re not using these yet, so keep disabled
        "extract_modules": False,
        "extract_secrets": False,
    }


def progress_printer(message: str, progress: float) -> None:
    """Simple progress callback that prints status to stdout."""
    pct = max(0.0, min(progress, 1.0)) * 100
    print(f"[{pct:5.1f}%] {message}")


def pretty_print_summary(results: Dict) -> None:
    """
    Print a small human-friendly summary from the analysis results and report.
    """
    session_dir = results.get("session_dir")
    report_path = results.get("report_json")

    print("\n=== VAST Evaluation Summary ===")
    print(f"Session directory : {session_dir or 'N/A'}")
    print(f"Raw memory file   : {results.get('raw_memory') or 'N/A'}")
    print(f"Memory JSON       : {results.get('memory_json') or 'N/A'}")
    print(f"File JSON         : {results.get('file_json') or 'N/A'}")
    print(f"Enhanced memory   : {results.get('memory_enhanced') or 'N/A'}")
    print(f"Enhanced files    : {results.get('file_enhanced') or 'N/A'}")
    print(f"VAST report JSON  : {report_path or 'N/A'}")

    # If a report exists, show key stats
    if report_path and Path(report_path).exists():
        try:
            data = json.loads(Path(report_path).read_text(encoding="utf-8"))
            summary = data.get("summary", {})
            print("\nArtifact counts:")
            print(f"  Processes found          : {summary.get('processes_found', 'N/A')}")
            print(f"  Network connections found: {summary.get('connections_found', 'N/A')}")
            print(f"  File objects found       : {summary.get('file_objects_found', 'N/A')}")
            print(f"  File handles found       : {summary.get('file_handles_found', 'N/A')}")
            print(f"  Suspicious processes     : {summary.get('suspicious_processes', 'N/A')}")
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("Could not read summary from report: %s", e)

    # Show any warnings / errors
    if results.get("warnings"):
        print("\nWarnings:")
        for w in results["warnings"]:
            print(f"  - {w}")

    if results.get("errors"):
        print("\nErrors:")
        for err in results["errors"]:
            print(f"  - {err}")


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the VAST analysis pipeline on a single snapshot for evaluation."
    )
    parser.add_argument(
        "--snapshot",
        "-s",
        type=str,
        help="Path to snapshot file (e.g. windows-snapshot.vmem, macOS-snapshot.vmem, ubuntu-snapshot.vmem). "
             "If omitted, the script will look for standard names in the project root.",
    )
    parser.add_argument(
        "--os",
        choices=["windows", "linux", "macos"],
        help="Operating system type. If omitted, it will be inferred from the snapshot filename.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    root = project_root()

    # Resolve snapshot path
    if args.snapshot:
        snapshot_path = (root / args.snapshot).resolve() if not Path(args.snapshot).is_absolute() \
            else Path(args.snapshot)
    else:
        snapshot_path = find_default_snapshot(root)
        if snapshot_path is None:
            print(
                "No snapshot provided and no default snapshot file found.\n"
                "Place one of the following into the project root or pass --snapshot:\n"
                f"  {', '.join(DEFAULT_SNAPSHOT_NAMES)}"
            )
            return 1

    if not snapshot_path.exists():
        print(f"Snapshot file not found: {snapshot_path}")
        return 1

    # Determine OS type
    if args.os:
        os_type = args.os.lower()
    else:
        try:
            os_type = infer_os_type(snapshot_path)
        except ValueError as e:
            print(str(e))
            return 1

    print(f"Using snapshot : {snapshot_path}")
    print(f"Detected OS    : {os_type}")
    print("Starting VAST analysis pipeline...\n")

    # Prepare analyzer
    analyzer = VASTAnalyzer(base_dir=root)
    analyzer.set_progress_callback(progress_printer)

    options = build_options(os_type)

    # Run the full pipeline
    results = analyzer.analyze_snapshot(
        snapshot_files=[snapshot_path],
        os_type=os_type,
        extract_processes=options["extract_processes"],
        extract_network=options["extract_network"],
        extract_files=options["extract_files"],
        extract_registry=options["extract_registry"],
        extract_modules=options["extract_modules"],
        extract_secrets=options["extract_secrets"],
    )

    if not results.get("success"):
        print("\nVAST analysis FAILED.")
        pretty_print_summary(results)
        return 1

    print("\nVAST analysis completed successfully.")
    pretty_print_summary(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
