#!/usr/bin/env python3
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
    """Get directory where this script is located."""
    return Path(__file__).resolve().parent


class MemoryArtifactExtractor:
    """
    Wraps Volatility 3 to extract memory artifacts (processes, network sockets).

    This assumes Volatility 3's `vol.py` is available either:
      - In the same folder as this script, or
      - At a custom path passed into the constructor.
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

        if self.os_type != "windows":
            self.result.warnings.append(
                f"OS type '{self.os_type}' not fully supported yet. "
                "Defaulting to Windows plugins."
            )

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
            plugin: e.g. 'windows.pslist.PsList' or 'windows.netscan.NetScan'
            plugin_args: extra args after plugin name, e.g. ['--pid', '4']
            extra_global_args: extra args before plugin name, e.g. ['-r', 'json']

        Returns:
            Parsed JSON object (structure is Volatility's own), or None on failure.
        """
        if plugin_args is None:
            plugin_args = []
        if extra_global_args is None:
            extra_global_args = []

        if not Path(self.raw_path).exists() or not self.vol_script.exists():
            # Warnings already recorded in __init__
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
            msg = (
                f"Failed to parse JSON from Volatility for plugin {plugin}: {e}. "
                f"First 500 chars of stdout: {stdout[:500]!r}"
            )
            logger.error(msg)
            self.result.warnings.append(msg)
            return None

    # ---------- High-level artifact extractors ----------

    def extract_processes(self) -> Any:
        """
        Extract process information using Volatility 3 (windows.pslist.PsList).
        """
        plugin = "windows.pslist.PsList"
        data = self._run_volatility(plugin)
        if data is None:
            self.result.warnings.append("Process extraction failed.")
            return []
        return data

    def extract_connections(self) -> Any:
        """
        Extract network connection/socket information (windows.netscan.NetScan).
        """
        plugin = "windows.netscan.NetScan"
        data = self._run_volatility(plugin)
        if data is None:
            self.result.warnings.append("Network connection extraction failed.")
            return []
        return data

    # ---------- Orchestrator ----------

    def run(self) -> Dict[str, Any]:
        """
        Run all extraction steps and build the final result dict.
        """
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
            self.result.warnings.append(
                "No processes or connections extracted. "
                "Image may be incompatible with Volatility 3 "
                "(no kernel layer / symbol table discovered)."
            )

        return self.result.to_dict()


# ---------- CLI entry point for standalone testing ----------

def print_pretty_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: List[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Memory Artifact Extractor: wraps Volatility 3 to obtain "
            "process and network artifacts from a raw memory dump."
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
             "If omitted, a default '<raw_stem>_extracted.json' will be created "
             "next to the raw file.",
    )

    args = parser.parse_args(argv)

    extractor = MemoryArtifactExtractor(
        raw_path=args.raw_file,
        os_type=args.os_type,
        vol_script=args.vol_path,
    )
    result = extractor.run()

    # Auto-generate output filename if not provided
    if args.output_json:
        out_path = Path(args.output_json).resolve()
    else:
        raw_path = Path(args.raw_file).resolve()
        out_path = raw_path.with_name(raw_path.stem + "_extracted.json")

    out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Extraction result written to %s", out_path)

    return 0 if result.get("success", False) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
