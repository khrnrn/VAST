#!/usr/bin/env python3
#file_extractor.py
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class FileActivityResult:
    success: bool
    input_raw: str
    os_type: str
    file_objects: Any = field(default_factory=list)
    recent_files: Any = field(default_factory=list)
    file_handles: Any = field(default_factory=list)
    registry_activity: Any = field(default_factory=list)
    prefetch_data: Any = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_script_dir() -> Path:
    """Get directory where this script is located."""
    return Path(__file__).resolve().parent


class FileActivityExtractor:
    """
    Wraps Volatility 3 to extract file and activity artifacts from memory dumps.
    
    This extracts:
    - File objects in memory
    - Recent files accessed
    - File handles by processes
    - Registry activity (RecentDocs, UserAssist)
    - Prefetch data
    """

    def __init__(
        self,
        raw_path: str,
        os_type: str = "windows",
        vol_script: Optional[str] = None,
    ) -> None:
        self.raw_path = str(Path(raw_path).resolve())
        self.os_type = os_type.lower().strip()
        self.vol_script = (
            Path(vol_script).resolve()
            if vol_script is not None
            else get_script_dir() / "vol.py"
        )

        self.result = FileActivityResult(
            success=False,
            input_raw=self.raw_path,
            os_type=self.os_type,
        )

        if not Path(self.raw_path).exists():
            self.result.warnings.append(f"Raw memory file not found: {self.raw_path}")

        if not self.vol_script.exists():
            self.result.warnings.append(
                f"Volatility script not found at: {self.vol_script}. "
                f"Place vol.py in the same folder or pass --vol-path."
            )

        if self.os_type not in ("windows", "linux"):
            self.result.warnings.append(f"OS type '{self.os_type}' not supported. Use 'windows' or 'linux'.")

    # ---------- Low-level Volatility wrapper ----------

    def _run_volatility(
        self,
        plugin: str,
        plugin_args: Optional[List[str]] = None,
        extra_global_args: Optional[List[str]] = None,
    ) -> Optional[Any]:
        """
        Run a Volatility 3 plugin and parse JSON output.

        Args:
            plugin: e.g. 'windows.filescan.FileScan'
            plugin_args: extra args after plugin name
            extra_global_args: extra args before plugin name

        Returns:
            Parsed JSON object (structure is Volatility's own), or None on failure.
        """
        if plugin_args is None:
            plugin_args = []
        if extra_global_args is None:
            extra_global_args = []

        if not Path(self.raw_path).exists() or not self.vol_script.exists():
            return None

        python_exec = sys.executable

        cmd = [
            python_exec,
            str(self.vol_script),
            "-f",
            self.raw_path,
            "-r",
            "json",
        ]
        cmd.extend(extra_global_args)
        cmd.append(plugin)
        cmd.extend(plugin_args)

        logger.info("Running Volatility: %s", " ".join(cmd))

        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=300,  # 5 minute timeout for slow operations
            )
        except subprocess.TimeoutExpired:
            msg = f"Volatility command timed out for plugin {plugin}"
            logger.error(msg)
            self.result.warnings.append(msg)
            return None
        except Exception as e:
            msg = f"Failed to execute Volatility: {e}"
            logger.error(msg)
            self.result.warnings.append(msg)
            return None

        if completed.returncode != 0:
            msg = (
                f"Volatility command failed (rc={completed.returncode}) "
                f"for plugin {plugin}. STDERR: {completed.stderr.strip()[:500]}"
            )
            logger.warning(msg)
            self.result.warnings.append(msg)
            return None

        stdout = completed.stdout.strip()
        if not stdout:
            msg = f"Volatility returned empty output for plugin {plugin}."
            logger.warning(msg)
            self.result.warnings.append(msg)
            return None

        try:
            data = json.loads(stdout)
            return data
        except json.JSONDecodeError as e:
            msg = (
                f"Failed to parse JSON from Volatility for plugin {plugin}: {e}. "
                f"First 500 chars of stdout: {stdout[:500]!r}"
            )
            logger.error(msg)
            self.result.warnings.append(msg)
            return None

    # ---------- High-level artifact extractors ----------

    def extract_file_objects(self) -> Any:
        if self.os_type == "linux":
            self.result.registry_activity = {}
            self.result.prefetch_data = []
        else:
            self.result.registry_activity = self.extract_registry_activity()
            self.result.prefetch_data = self.extract_prefetch()
        plugin = "windows.filescan.FileScan"
        data = self._run_volatility(plugin)
        if data is None:
            self.result.warnings.append("File object extraction failed.")
            return []
        return data

    def extract_file_handles(self) -> Any:
        """
        Extract file handles using windows.handles.Handles.
        This shows which processes have open file handles.
        """
        logger.info("Extracting file handles...")
        if self.os_type == "linux":
            # lsof already shows open files per process
            return self.extract_file_objects()  # reuse
        else:
            plugin = "windows.handles.Handles"
            # Filter for File type handles
            data = self._run_volatility(plugin, plugin_args=["--pid", "4"])  # System process often has many handles
        if data is None:
            self.result.warnings.append("File handle extraction failed.")
            return []
        
        # Filter for file-type handles
        if isinstance(data, list):
            file_handles = [
                item for item in data 
                if isinstance(item, dict) and 
                str(item.get("Type", "")).lower() in ["file", "key"]
            ]
            return file_handles
        return data

    def extract_registry_activity(self) -> Any:
        """
        Extract registry activity using multiple plugins:
        - windows.registry.hivelist.HiveList (list registry hives)
        - windows.registry.userassist.UserAssist (recent program execution)
        """
        logger.info("Extracting registry activity...")
        registry_data = {}
        
        # Get hive list
        plugin = "windows.registry.hivelist.HiveList"
        hives = self._run_volatility(plugin)
        if hives:
            registry_data["hives"] = hives
        else:
            self.result.warnings.append("Registry hive list extraction failed.")
        
        # Get UserAssist data (recent program execution)
        plugin = "windows.registry.userassist.UserAssist"
        userassist = self._run_volatility(plugin)
        if userassist:
            registry_data["user_assist"] = userassist
        else:
            self.result.warnings.append("UserAssist extraction failed.")
        
        return registry_data

    def extract_bash_history(self) -> Any:
        if self.os_type != "linux":
            return []
        plugin = "linux.bash.Bash"
        data = self._run_volatility(plugin)
        return data or []

    def extract_recent_files(self) -> Any:
        """
        Extract recent files from registry and other sources.
        Uses windows.registry.printkey.PrintKey to find RecentDocs.
        """
        logger.info("Extracting recent files...")
        if self.os_type == "linux":
            return self.extract_bash_history()
        else:
            # Try to extract RecentDocs from registry
            plugin = "windows.registry.printkey.PrintKey"
            # Common path for recent documents
            recent_docs = self._run_volatility(
                plugin,
                plugin_args=["--key", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"]
            )
        if recent_docs is None:
            self.result.warnings.append("Recent files extraction failed.")
            return []
        return recent_docs

    def extract_prefetch(self) -> Any:
        """
        Extract prefetch data if available.
        Note: This may not be directly available in all memory dumps.
        """
        logger.info("Extracting prefetch data...")
        # Prefetch data extraction is limited in memory forensics
        # We'll try to find prefetch-related file objects
        plugin = "windows.filescan.FileScan"
        data = self._run_volatility(plugin)
        
        if data and isinstance(data, list):
            # Filter for .pf files (prefetch files)
            prefetch_files = [
                item for item in data
                if isinstance(item, dict) and
                str(item.get("FileName", "")).lower().endswith(".pf")
            ]
            return prefetch_files
        
        self.result.warnings.append("Prefetch extraction limited - no .pf files found.")
        return []

    # ---------- Orchestrator ----------

    def run(self) -> Dict[str, Any]:
        """
        Run all file/activity extraction steps and build the final result dict.
        """
        if not Path(self.raw_path).exists() or not self.vol_script.exists():
            self.result.success = False
            return self.result.to_dict()

        logger.info("Starting file/activity artifact extraction for %s", self.raw_path)

        # Extract all artifacts
        self.result.file_objects = self.extract_file_objects()
        self.result.file_handles = self.extract_file_handles()
        self.result.registry_activity = self.extract_registry_activity()
        self.result.recent_files = self.extract_recent_files()
        self.result.prefetch_data = self.extract_prefetch()

        # Check if we got any data
        has_data = (
            self.result.file_objects or 
            self.result.file_handles or 
            self.result.registry_activity or
            self.result.recent_files or
            self.result.prefetch_data
        )

        if has_data:
            self.result.success = True
            logger.info("File/activity extraction completed successfully")
        else:
            self.result.success = False
            self.result.warnings.append(
                "No file/activity artifacts extracted. "
                "Image may be incompatible with Volatility 3 "
                "(no kernel layer / symbol table discovered)."
            )

        return self.result.to_dict()


# ---------- CLI entry point ----------

def print_pretty_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "File Activity Extractor: wraps Volatility 3 to obtain "
            "file objects, handles, registry activity, and recent files from memory."
        )
    )
    parser.add_argument(
        "raw_file",
        help="Path to raw memory dump (output_raw from parser.py)",
    )
    parser.add_argument(
        "--os",
        dest="os_type",
        default="windows",
        help="Guest OS type (currently only 'windows' is supported).",
    )
    parser.add_argument(
        "--vol-path",
        dest="vol_path",
        default=None,
        help="Path to Volatility 3 vol.py script. "
             "Defaults to ./vol.py next to this script.",
    )
    parser.add_argument(
        "--output",
        dest="output_json",
        default=None,
        help="Optional path to save extraction result as JSON. "
             "If omitted, a default '<raw_stem>_file_activity.json' will be created "
             "in the output/ folder.",
    )
    parser.add_argument(
        "--session", 
        help="Session directory from vast.py"
    )

    args = parser.parse_args(argv)

    extractor = FileActivityExtractor(
        raw_path=args.raw_file,
        os_type=args.os_type,
        vol_script=args.vol_path,
    )
    result = extractor.run()

    # Auto-generate output filename if not provided
    if args.output_json:
        out_path = Path(args.output_json).resolve()
    else:
        # Create output directory if it doesn't exist
        if args.session:
            output_dir = Path(args.session) / "extracted_files"
        else:
            output_dir = get_script_dir() / "output" / "extracted_files"

        output_dir.mkdir(parents=True, exist_ok=True)
        
        raw_path = Path(args.raw_file).resolve()
        out_path = output_dir / f"{raw_path.stem}_file_activity.json"

    out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("File/activity extraction result written to %s", out_path)

    # Print summary
    print("\n" + "="*60)
    print("FILE/ACTIVITY EXTRACTION SUMMARY")
    print("="*60)
    print(f"Success: {result.get('success', False)}")
    print(f"Input: {result.get('input_raw', 'N/A')}")
    print(f"Output: {out_path}")
    print(f"\nArtifacts Extracted:")
    print(f"  - File Objects: {len(result.get('file_objects', []))}")
    print(f"  - File Handles: {len(result.get('file_handles', []))}")
    print(f"  - Registry Data: {len(result.get('registry_activity', {}))}")
    print(f"  - Recent Files: {len(result.get('recent_files', []))}")
    print(f"  - Prefetch Files: {len(result.get('prefetch_data', []))}")
    
    if result.get('warnings'):
        print(f"\nWarnings ({len(result['warnings'])}):")
        for warning in result['warnings']:
            print(f" [WARNING] {warning}")
    print("="*60 + "\n")

    return 0 if result.get("success", False) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))