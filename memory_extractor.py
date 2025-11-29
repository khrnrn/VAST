#!/usr/bin/env python3
# memory_extractor.py
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
class MemoryExtractionResult:
    success: bool
    input_raw: str
    os_type: str
    processes: Any = field(default_factory=list)
    connections: Any = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_script_dir() -> Path:
    return Path(__file__).resolve().parent


class MemoryArtifactExtractor:
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

        self.result = MemoryExtractionResult(
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

        # Inject Linux ISF if needed — NO trailing spaces!
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

    def extract_processes(self) -> Any:
        if self.os_type == "linux":
            plugin = "linux.pslist.PsList"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Process extraction failed.")
                return []

            # Handle {"rows": [...], "columns": [...]} format
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
                    entries = list(data.values())  # fallback
            elif isinstance(data, list):
                entries = data

            normalized = []
            for p in entries:
                if not isinstance(p, dict):
                    continue
                normalized.append({
                    "PID": p.get("PID") or p.get("pid", 0),
                    "ImageFileName": p.get("COMM") or p.get("comm", "unknown"),
                    "PPID": p.get("PPID") or p.get("ppid", 0),
                    "ImagePath": p.get("executable", ""),
                    "CommandLine": "",
                    "Threads": p.get("num_threads", 0),
                    "Wow64": False,
                    "SessionId": None,
                    "User": p.get("uid", "Unknown"),
                })
            return normalized
        else:
            plugin = "windows.pslist.PsList"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Process extraction failed.")
                return []
            return data

    def extract_connections(self) -> Any:
        if self.os_type == "linux":
            plugin = "linux.sockstat.Sockstat"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Network connection extraction failed.")
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
            for sock in entries:
                if not isinstance(sock, dict):
                    continue
                normalized.append({
                    "Proto": sock.get("Protocol", "TCP"),
                    "LocalAddr": str(sock.get("LocalAddr", "0.0.0.0")),
                    "LocalPort": int(sock.get("LocalPort", 0)),
                    "ForeignAddr": str(sock.get("ForeignAddr", "0.0.0.0")),
                    "ForeignPort": int(sock.get("ForeignPort", 0)),
                    "State": sock.get("State", "UNKNOWN"),
                    "PID": sock.get("PID") or sock.get("pid", 0),
                    "Owner": sock.get("Process") or sock.get("process", ""),
                })
            return normalized
        else:
            plugin = "windows.netscan.NetScan"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Network connection extraction failed.")
                return []
            return data

    def run(self) -> Dict[str, Any]:
        if not Path(self.raw_path).exists() or not self.vol_script.exists():
            self.result.success = False
            return self.result.to_dict()

        logger.info("Starting memory artifact extraction for %s", self.raw_path)

        self.result.processes = self.extract_processes()
        self.result.connections = self.extract_connections()

        if self.result.processes or self.result.connections:
            self.result.success = True
        else:
            self.result.success = False
            self.result.warnings.append("No processes or connections extracted.")
        return self.result.to_dict()


def main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Memory Artifact Extractor")
    parser.add_argument("raw_file", help="Path to raw memory dump")
    parser.add_argument("--os", default="windows", help="Guest OS type")
    parser.add_argument("--vol-path", default=None, help="Path to vol.py")
    parser.add_argument("--output", default=None, help="Output JSON path")
    parser.add_argument("--session", help="Session directory")

    args = parser.parse_args(argv)

    extractor = MemoryArtifactExtractor(
        raw_path=args.raw_file,
        os_type=args.os,
        vol_script=args.vol_path,
    )
    result = extractor.run()

    if args.output:
        out_path = Path(args.output).resolve()
    else:
        output_dir = Path(args.session) / "extracted_memory" if args.session else get_script_dir() / "output" / "extracted_memory"
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = Path(args.raw_file).resolve()
        out_path = output_dir / f"{raw_path.stem}_memory.json"

    out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Extraction result written to %s", out_path)

    return 0 if result.get("success", False) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))