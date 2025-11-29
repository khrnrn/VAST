#!/usr/bin/env python3
# file_extractor.py
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    registry_activity: Any = field(default_factory=dict)
    prefetch_data: Any = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_script_dir() -> Path:
    return Path(__file__).resolve().parent


class FileActivityExtractor:
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

    def _run_volatility(
        self,
        plugin: str,
        plugin_args: Optional[List[str]] = None,
        extra_global_args: Optional[List[str]] = None,
    ) -> Optional[Any]:
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

        # Inject Linux ISF — NO trailing spaces!
        effective_extra_args = extra_global_args.copy()
        if self.os_type == "linux":
            has_isf = any(arg == "-u" for arg in effective_extra_args)
            if not has_isf:
                effective_extra_args = ["-u", "https://github.com/leludo84/vol3-linux-profiles/blob/main/banners-isf.json"] + effective_extra_args

        cmd.extend(effective_extra_args)
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
                # NO TIMEOUT
            )
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
            msg = f"Failed to parse JSON from Volatility for plugin {plugin}: {e}"
            logger.error(msg)
            self.result.warnings.append(msg)
            return None

    def extract_file_objects(self) -> Any:
        if self.os_type == "linux":
            plugin = "linux.lsof.Lsof"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Linux file object extraction (lsof) failed.")
                return []

            entries = []
            if isinstance(data, dict):
                if "rows" in data:
                    columns = data.get("columns", [])
                    for row in data["rows"]:
                        entry = dict(zip(columns, row))
                        entries.append(entry)
                elif "entries" in data:
                    entries = data["entries"]
                else:
                    entries = list(data.values())
            elif isinstance(data, list):
                entries = data

            normalized = []
            for item in entries:
                if not isinstance(item, dict):
                    continue
                normalized.append({
                    "FileName": item.get("path", item.get("Path", "")),
                    "PID": item.get("pid", item.get("PID", 0)),
                    "FD": item.get("fd", item.get("FD", "")),
                    "Type": item.get("type", item.get("Type", "")),
                    "Offset": item.get("inode", item.get("Inode", "")),
                    "Process": item.get("process", item.get("Process", "")),
                })
            return normalized
        else:
            plugin = "windows.filescan.FileScan"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("File object extraction failed.")
                return []
            return data

    def extract_file_handles(self) -> Any:
        logger.info("Extracting file handles...")
        if self.os_type == "linux":
            return self.extract_file_objects()
        else:
            plugin = "windows.handles.Handles"
            data = self._run_volatility(plugin, plugin_args=["--pid", "4"])
            if data is None:
                self.result.warnings.append("File handle extraction failed.")
                return []
            if isinstance(data, list):
                file_handles = [
                    item for item in data
                    if isinstance(item, dict) and str(item.get("Type", "")).lower() in ["file", "key"]
                ]
                return file_handles
            return data

    def extract_registry_activity(self) -> Any:
        if self.os_type == "linux":
            return {}
        logger.info("Extracting registry activity...")
        registry_data = {}
        plugin = "windows.registry.hivelist.HiveList"
        hives = self._run_volatility(plugin)
        if hives:
            registry_data["hives"] = hives
        else:
            self.result.warnings.append("Registry hive list extraction failed.")
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
        if data is None:
            return []

        entries = []
        if isinstance(data, dict):
            if "rows" in data:
                columns = data.get("columns", [])
                for row in data["rows"]:
                    entry = dict(zip(columns, row))
                    entries.append(entry)
            elif "entries" in data:
                entries = data["entries"]
            else:
                entries = list(data.values())
        elif isinstance(data, list):
            entries = data

        # Return list of command strings or full dicts
        result = []
        for e in entries:
            if isinstance(e, dict):
                cmd = e.get("Command", e.get("command", ""))
                if cmd:
                    result.append(cmd)
            elif isinstance(e, str):
                result.append(e)
        return result

    def extract_recent_files(self) -> Any:
        logger.info("Extracting recent files...")
        if self.os_type == "linux":
            return self.extract_bash_history()
        else:
            plugin = "windows.registry.printkey.PrintKey"
            recent_docs = self._run_volatility(
                plugin,
                plugin_args=["--key", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"]
            )
            if recent_docs is None:
                self.result.warnings.append("Recent files extraction failed.")
                return []
            return recent_docs

    def extract_prefetch(self) -> Any:
        if self.os_type == "linux":
            return []
        logger.info("Extracting prefetch data...")
        plugin = "windows.filescan.FileScan"
        data = self._run_volatility(plugin)
        if data and isinstance(data, list):
            prefetch_files = [
                item for item in data
                if isinstance(item, dict) and str(item.get("FileName", "")).lower().endswith(".pf")
            ]
            return prefetch_files
        self.result.warnings.append("Prefetch extraction limited - no .pf files found.")
        return []

    def run(self) -> Dict[str, Any]:
        if not Path(self.raw_path).exists() or not self.vol_script.exists():
            self.result.success = False
            return self.result.to_dict()

        logger.info("Starting file/activity artifact extraction for %s", self.raw_path)

        self.result.file_objects = self.extract_file_objects()
        self.result.file_handles = self.extract_file_handles()
        self.result.registry_activity = self.extract_registry_activity()
        self.result.recent_files = self.extract_recent_files()
        self.result.prefetch_data = self.extract_prefetch()

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
            self.result.warnings.append("No file/activity artifacts extracted.")
        return self.result.to_dict()


def main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="File Activity Extractor")
    parser.add_argument("raw_file", help="Path to raw memory dump")
    parser.add_argument("--os", default="windows", help="Guest OS type")
    parser.add_argument("--vol-path", default=None, help="Path to vol.py")
    parser.add_argument("--output", default=None, help="Output JSON path")
    parser.add_argument("--session", help="Session directory")

    args = parser.parse_args(argv)

    extractor = FileActivityExtractor(
        raw_path=args.raw_file,
        os_type=args.os,
        vol_script=args.vol_path,
    )
    result = extractor.run()

    if args.output:
        out_path = Path(args.output).resolve()
    else:
        output_dir = Path(args.session) / "extracted_files" if args.session else get_script_dir() / "output" / "extracted_files"
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = Path(args.raw_file).resolve()
        out_path = output_dir / f"{raw_path.stem}_file_activity.json"

    out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("File/activity extraction result written to %s", out_path)

    print("\n" + "=" * 60)
    print("FILE/ACTIVITY EXTRACTION SUMMARY")
    print("=" * 60)
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
    print("=" * 60 + "\n")

    return 0 if result.get("success", False) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))