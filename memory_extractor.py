#!/usr/bin/env python3
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

        if self.os_type not in ("windows", "linux", "macos"):
            self.result.warnings.append(f"OS type '{self.os_type}' not supported. Use 'windows', 'linux', or 'macos'.")

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

        # Inject symbol files for Linux and macOS
        effective_extra_args = extra_global_args.copy()
        if self.os_type == "linux":
            has_isf = any(arg == "-u" for arg in effective_extra_args)
            if not has_isf:
                effective_extra_args = ["-u", "https://raw.githubusercontent.com/leludo84/vol3-linux-profiles/main/banners-isf.json"] + effective_extra_args
        elif self.os_type == "macos":
            has_isf = any(arg == "-u" for arg in effective_extra_args)
            if not has_isf:
                effective_extra_args = ["-u", "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json"] + effective_extra_args

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

            # DEBUG: Print raw data structure
            logger.info("=" * 60)
            logger.info("DEBUG: Linux raw data type: %s", type(data))
            if isinstance(data, (list, dict)) and data:
                sample = data[0] if isinstance(data, list) else list(data.values())[0] if isinstance(data, dict) else {}
                logger.info("DEBUG: First entry sample: %s", json.dumps(sample, indent=2) if isinstance(sample, dict) else str(sample))
            logger.info("=" * 60)

            entries = []
            if isinstance(data, list):
                # Direct list of dicts
                entries = [item for item in data if isinstance(item, dict)]
            elif isinstance(data, dict):
                # Check for different structures
                if "__children" in data:
                    # Volatility tree structure
                    entries = data.get("__children", [])
                else:
                    # Flat dict structure
                    entries = [v for v in data.values() if isinstance(v, dict)]

            normalized = []
            for p in entries:
                if not isinstance(p, dict):
                    continue
                
                # Extract process name - try ALL possible field names
                process_name = (
                    p.get("COMM") or 
                    p.get("comm") or
                    p.get("NAME") or 
                    p.get("name") or
                    p.get("ImageFileName") or
                    p.get("Command") or
                    p.get("command") or
                    "unknown"
                )
                
                logger.debug("Process: %s (PID: %s)", process_name, p.get("PID") or p.get("pid"))
                
                normalized.append({
                    "PID": p.get("PID") or p.get("pid", 0),
                    "ImageFileName": process_name,
                    "comm": process_name,
                    "PPID": p.get("PPID") or p.get("ppid", 0),
                    "ImagePath": p.get("executable", ""),
                    "CommandLine": "",
                    "Threads": p.get("num_threads", 0),
                    "Wow64": False,
                    "SessionId": None,
                    "User": p.get("UID") or p.get("uid", "Unknown"),
                })
            
            logger.info("Normalized %d Linux processes", len(normalized))
            return normalized
        
        elif self.os_type == "macos":
            plugin = "mac.pslist.PsList"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Process extraction failed.")
                return []

            # DEBUG: Print raw data structure
            logger.info("=" * 60)
            logger.info("DEBUG: macOS raw data type: %s", type(data))
            if isinstance(data, (list, dict)) and data:
                sample = data[0] if isinstance(data, list) else list(data.values())[0] if isinstance(data, dict) else {}
                logger.info("DEBUG: First entry sample: %s", json.dumps(sample, indent=2) if isinstance(sample, dict) else str(sample))
            logger.info("=" * 60)

            entries = []
            if isinstance(data, list):
                # Direct list of dicts
                entries = [item for item in data if isinstance(item, dict)]
            elif isinstance(data, dict):
                # Check for different structures
                if "__children" in data:
                    # Volatility tree structure
                    entries = data.get("__children", [])
                else:
                    # Flat dict structure
                    entries = [v for v in data.values() if isinstance(v, dict)]

            normalized = []
            for p in entries:
                if not isinstance(p, dict):
                    continue
                
                # Extract process name - try ALL possible field names
                process_name = (
                    p.get("NAME") or 
                    p.get("name") or 
                    p.get("COMM") or 
                    p.get("comm") or
                    p.get("ImageFileName") or
                    p.get("Command") or
                    p.get("command") or
                    "unknown"
                )
                
                logger.debug("Process: %s (PID: %s)", process_name, p.get("PID") or p.get("pid"))
                
                normalized.append({
                    "PID": p.get("PID") or p.get("pid", 0),
                    "ImageFileName": process_name,
                    "comm": process_name,
                    "PPID": p.get("PPID") or p.get("ppid", 0),
                    "ImagePath": p.get("path", ""),
                    "CommandLine": "",
                    "Threads": p.get("num_threads", 0),
                    "Wow64": False,
                    "SessionId": None,
                    "User": p.get("UID") or p.get("uid", "Unknown"),
                })
            
            logger.info("Normalized %d macOS processes", len(normalized))
            return normalized
        
        else:  # Windows
            plugin = "windows.pslist.PsList"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Process extraction failed.")
                return []
            
            # Windows data is usually already in the right format
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
        
        elif self.os_type == "macos":
            plugin = "mac.netstat.Netstat"
            data = self._run_volatility(plugin)
            if data is None:
                self.result.warnings.append("Network connection extraction failed.")
                return []

            # DEBUG: Log what we received
            logger.info("macOS netstat data type: %s", type(data))
            if isinstance(data, dict):
                logger.info("Data keys: %s", list(data.keys()))
                if "__children" in data:
                    logger.info("Found %d children", len(data["__children"]))
                    if data["__children"]:
                        logger.info("First child sample: %s", data["__children"][0])

            entries = []
            
            # Volatility 3 JSON format with __children
            if isinstance(data, dict) and "__children" in data:
                for child in data["__children"]:
                    if not isinstance(child, dict):
                        continue
                    
                    proto = str(child.get("Proto", "")).strip().upper()
                    
                    # Skip UNIX sockets - only keep TCP/UDP
                    if proto not in ['TCP', 'UDP', 'TCPV4', 'TCPV6', 'UDPV4', 'UDPV6']:
                        continue
                    
                    # Check if Local IP is actually an IP address, not a file path
                    local_ip = str(child.get("Local IP", "")).strip()
                    if local_ip.startswith('/') or local_ip.startswith('\\'):
                        # This is a UNIX socket path, skip it
                        continue
                    
                    entries.append(child)
                    
            elif isinstance(data, list):
                # Direct list of dictionaries
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    
                    proto = str(item.get("Proto", "")).strip().upper()
                    if proto not in ['TCP', 'UDP', 'TCPV4', 'TCPV6', 'UDPV4', 'UDPV6']:
                        continue
                    
                    local_ip = str(item.get("Local IP", "")).strip()
                    if local_ip.startswith('/') or local_ip.startswith('\\'):
                        continue
                    
                    entries.append(item)
            
            logger.info("Filtered to %d TCP/UDP connections (excluded UNIX sockets)", len(entries))

            normalized = []
            for sock in entries:
                # Get values with exact Volatility 3 column names
                local_ip = str(sock.get("Local IP", "0.0.0.0")).strip()
                local_port = sock.get("Local Port", 0)
                remote_ip = str(sock.get("Remote IP", "0.0.0.0")).strip()
                remote_port = sock.get("Remote Port", 0)
                proto = str(sock.get("Proto", "TCP")).strip().upper()
                state = str(sock.get("State", "")).strip()
                process = str(sock.get("Process", "")).strip()
                
                # Clean up protocol name (remove v4/v6)
                proto = proto.replace('V4', '').replace('V6', '')
                
                # Extract PID from "Process" field (format: "processname/pid")
                pid = 0
                if process and '/' in process:
                    parts = process.split('/')
                    if len(parts) == 2 and parts[1].isdigit():
                        pid = int(parts[1])
                        process_name = parts[0]
                    else:
                        process_name = process
                else:
                    process_name = process
                
                # Convert port to int if it's a string
                try:
                    local_port = int(local_port) if local_port else 0
                except (ValueError, TypeError):
                    local_port = 0
                
                try:
                    remote_port = int(remote_port) if remote_port else 0
                except (ValueError, TypeError):
                    remote_port = 0
                
                normalized.append({
                    "Proto": proto,
                    "LocalAddr": local_ip,
                    "LocalPort": local_port,
                    "ForeignAddr": remote_ip,
                    "ForeignPort": remote_port,
                    "State": state,
                    "PID": pid,
                    "Owner": process_name,
                })
            
            logger.info("Successfully normalized %d macOS network connections", len(normalized))
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
    parser.add_argument("--os", default="windows", help="Guest OS type (windows/linux/macos)")
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