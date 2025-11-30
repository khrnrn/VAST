#!/usr/bin/env python3
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MITRE_MAP = {
    "powershell.exe": "T1059 - Command & Scripting Interpreter",
    "cmd.exe": "T1059 - Command & Scripting Interpreter",
    "wscript.exe": "T1059.005 - VBScript",
    "cscript.exe": "T1059.007 - JavaScript",
    "rundll32.exe": "T1218 - Signed Binary Proxy Execution",
    "wmic.exe": "T1047 - Windows Management Instrumentation",
    "svchost.exe": "T1543 - Create or Modify System Process",
    "regsvr32.exe": "T1218 - Script Execution",
    "mshta.exe": "T1218 - HTML Application Execution",
    "iexplore.exe": "T1105 - Exfiltration/Browser",
    "chrome.exe": "T1105 - Exfiltration/Browser"
}

WINDOWS_SYSTEM_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", 
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchapp.exe", "dllhost.exe"
}

def detect_process_red_flags(processes):
    red_flags = []

    for p in processes:
        if not isinstance(p, dict):
            continue
            
        name = str(p.get("ImageFileName", "")).lower().strip().replace("\u0000", "")
        
        # Skip whitelisted Windows processes for MITRE detection
        if name in WINDOWS_SYSTEM_PROCESSES:
            continue  # Don't flag normal Windows processes
        
        path = str(p.get("ImagePath", p.get("path", ""))).lower()
        threads = p.get("Threads", 0)
        cmd = str(p.get("CommandLine", "")).lower()

        # Only flag suspicious paths (not system32)
        if path and "appdata" in path or "temp" in path or "downloads" in path:
            if "\\windows\\system32\\" not in path:
                red_flags.append(f"{name} running from suspicious path: {path}")

        # Only flag very high thread counts (>100)
        if isinstance(threads, int) and threads > 100:
            red_flags.append(f"{name} has unusually high thread count: {threads}")

        # Check for encoded commands
        if cmd and ("encodedcommand" in cmd or " -e " in cmd or "-enc" in cmd):
            red_flags.append(f"[CRITICAL] {name} using encoded PowerShell commands")

        # Only flag non-system processes for MITRE
        if name and name in MITRE_MAP and name not in WINDOWS_SYSTEM_PROCESSES:
            red_flags.append(f"{name} linked to MITRE: {MITRE_MAP[name]}")

    return red_flags


def detect_network_anomalies(conns):
    anomalies = []

    for c in conns:
        if not isinstance(c, dict):
            continue
            
        port = str(c.get("ForeignPort", ""))
        ip = str(c.get("ForeignAddr", ""))
        state = str(c.get("State", "")).upper()

        # Skip localhost, empty IPs, and CLOSED connections
        if not ip or ip in ["0.0.0.0", "127.0.0.1", "::1", "*", "None", ":::0"]:
            continue
        
        if state in ["CLOSED", "CLOSE_WAIT", "TIME_WAIT"]:
            continue  # Skip closed connections

        # Only report ESTABLISHED or LISTENING external connections
        if state in ["ESTABLISHED", "LISTENING"]:
            anomalies.append(f"Active connection to {ip}:{port} [{state}]")

        # Flag suspicious ports
        if port in ["4444", "1337", "8081", "31337"]:
            anomalies.append(f"[CRITICAL] Connection to C2 port {port} → {ip}")

    return anomalies


def detect_persistence(file_artifacts):
    persistence = []

    for f in file_artifacts:
        if not isinstance(f, (dict, str)):
            continue
            
        # Handle both dict and string formats
        if isinstance(f, dict):
            path = str(f.get("FileName", f.get("FilePath", ""))).lower()
        else:
            path = str(f).lower()

        if not path:
            continue

        # Check for persistence indicators
        if "\\run" in path and "microsoft" in path:
            persistence.append(f"Autorun registry key: {path}")

        if "\\startup" in path or "\\start menu\\programs\\startup" in path:
            persistence.append(f"Startup folder entry: {path}")

        if path.endswith(".lnk") and ("startup" in path or "run" in path):
            persistence.append(f"Suspicious autorun shortcut: {path}")

    return persistence


def get_script_dir() -> Path:
    return Path(__file__).resolve().parent


class AutomatedAnalyzer:
    """
    Analyzes memory dumps and extraction JSONs to answer common forensic questions.
    """
    
    def __init__(self, raw_path: str, memory_json: str, file_json: str, vol_script: Optional[str] = None):
        self.raw_path = Path(raw_path).resolve()
        self.memory_json = Path(memory_json).resolve()
        self.file_json = Path(file_json).resolve()
        self.vol_script = (
            Path(vol_script).resolve()
            if vol_script is not None
            else get_script_dir() / "vol.py"
        )
        
        self.analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "system_info": {},
            "process_analysis": {},
            "network_analysis": {},
            "file_analysis": {},
            "registry_analysis": {},
            "suspicious_findings": [],
            "summary": {}
        }
    
    def _run_volatility(self, plugin: str, plugin_args: Optional[List[str]] = None) -> Optional[Any]:
        """Run Volatility plugin and return JSON output."""
        if plugin_args is None:
            plugin_args = []
        
        if not self.raw_path.exists() or not self.vol_script.exists():
            return None
        
        cmd = [
            sys.executable,
            str(self.vol_script),
            "-f", str(self.raw_path),
            "-r", "json",
            plugin
        ] + plugin_args
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=120
            )
            
            if result.returncode != 0:
                return None
            
            return json.loads(result.stdout.strip()) if result.stdout.strip() else None
        except Exception as e:
            logger.error(f"Volatility command failed: {e}")
            return None
    
    def analyze_system_info(self):
            """Extract basic system information - NOW SUPPORTS WINDOWS, LINUX, AND MACOS."""
            logger.info("Analyzing system information...")
            
            # Determine OS type from the raw memory file path or memory extraction results
            os_type = "unknown"
            
            # Try to detect OS type from memory extraction results
            try:
                with open(self.memory_json, "r") as f:
                    mem_data = json.load(f)
                    os_type = mem_data.get("os_type", "unknown").lower()
            except Exception:
                pass
            
            logger.info(f"Detected OS type: {os_type}")
            
            # === WINDOWS SYSTEM INFO ===
            if os_type == "windows":
                # Get system info from windows.info plugin
                info_data = self._run_volatility("windows.info.Info")
                
                if info_data:
                    self.analysis_results["system_info"] = {
                        "plugin_output": info_data
                    }
                
                # Extract computer name and usernames from registry
                env_data = self._run_volatility("windows.envars.Envars")
                
                if env_data and isinstance(env_data, list):
                    usernames_set = set()
                    for entry in env_data:
                        if isinstance(entry, dict):
                            var_name = entry.get("Variable", "")
                            if var_name == "COMPUTERNAME":
                                self.analysis_results["system_info"]["computer_name"] = entry.get("Value", "Unknown")
                            elif var_name == "USERNAME":
                                username = entry.get("Value")
                                if username:
                                    usernames_set.add(username)
                    
                    self.analysis_results["system_info"]["usernames"] = sorted(list(usernames_set))
            
            # === LINUX SYSTEM INFO ===
            elif os_type == "linux":
                logger.info("Extracting Linux system information...")
                
                # Get hostname from linux.hostname plugin (if available)
                # Note: This plugin may not exist in all Volatility 3 versions
                hostname = "Unknown"
                
                # Try to extract hostname from bash history or process command lines
                bash_data = self._run_volatility("linux.bash.Bash")
                if bash_data:
                    # Look for hostname in bash commands
                    for entry in bash_data if isinstance(bash_data, list) else []:
                        if isinstance(entry, dict):
                            cmd = entry.get("Command", "")
                            if "hostname" in cmd.lower():
                                # Try to extract hostname from command output
                                parts = cmd.split()
                                if len(parts) > 1:
                                    hostname = parts[1]
                                    break
                
                # Get kernel version from memory extraction data
                os_version = "Linux"
                try:
                    with open(self.memory_json, "r") as f:
                        mem_data = json.load(f)
                        # Check if there's kernel info in processes
                        processes = mem_data.get("processes", [])
                        if processes:
                            # Look for kernel version in first process or system info
                            os_version = "Linux (Kernel detected)"
                except Exception:
                    pass
                
                # Extract usernames from process user IDs
                usernames_set = set()
                try:
                    with open(self.memory_json, "r") as f:
                        mem_data = json.load(f)
                        processes = mem_data.get("processes", [])
                        
                        for proc in processes:
                            user = proc.get("User") or proc.get("user") or proc.get("UID") or proc.get("uid")
                            if user and str(user).isdigit():
                                # UID - try to map common UIDs to usernames
                                uid = int(user)
                                if uid >= 1000:  # Regular user UIDs typically start at 1000
                                    # Extract from process paths
                                    path = str(proc.get("ImagePath", ""))
                                    if "/home/" in path:
                                        username = path.split("/home/")[1].split("/")[0]
                                        if username:
                                            usernames_set.add(username)
                            elif user and not str(user).isdigit():
                                # Username directly available
                                if user not in ["root", "daemon", "bin", "sys"]:
                                    usernames_set.add(user)
                except Exception as e:
                    logger.warning(f"Could not extract Linux usernames: {e}")
                
                self.analysis_results["system_info"] = {
                    "computer_name": hostname,
                    "hostname": hostname,
                    "os_version": os_version,
                    "usernames": sorted(list(usernames_set)),
                    "plugin_output": []  # Linux doesn't have the same plugin output structure
                }
            
            # === MACOS SYSTEM INFO ===
            elif os_type == "macos":
                logger.info("Extracting macOS system information...")
                
                hostname = "Unknown"
                os_version = "macOS"
                architecture = "Unknown"
                
                # Try to get OS version from banners plugin first
                try:
                    banners_data = self._run_volatility("banners.Banners")
                    if banners_data:
                        logger.info(f"Banners data type: {type(banners_data)}")
                        logger.info(f"Banners data content: {banners_data}")
                        
                        # Extract Darwin kernel info from banners
                        banner_text = None
                        
                        # Handle list format (common in Volatility 3)
                        if isinstance(banners_data, list):
                            for entry in banners_data:
                                if isinstance(entry, dict):
                                    banner = str(entry.get("Banner", ""))
                                    if "Darwin" in banner and "Kernel" in banner:
                                        banner_text = banner
                                        break
                        
                        # Handle dict with __children
                        elif isinstance(banners_data, dict):
                            if "__children" in banners_data:
                                for entry in banners_data["__children"]:
                                    if isinstance(entry, dict):
                                        banner = str(entry.get("Banner", ""))
                                        if "Darwin" in banner and "Kernel" in banner:
                                            banner_text = banner
                                            break
                            else:
                                # Single banner in dict format
                                banner = str(banners_data.get("Banner", ""))
                                if "Darwin" in banner:
                                    banner_text = banner
                        
                        # Parse the banner if found
                        if banner_text:
                            logger.info(f"Found Darwin banner: {banner_text}")
                            os_version = banner_text
                            
                            try:
                                # Extract Darwin version number
                                if "Darwin Kernel Version" in banner_text:
                                    version_part = banner_text.split("Version ")[1].split(":")[0]
                                    darwin_ver = version_part.split(".")[0]
                                    darwin_major = int(darwin_ver)
                                    
                                    logger.info(f"Parsed Darwin version: {darwin_major}")
                                    
                                    # Map Darwin version to macOS version
                                    if darwin_major >= 23:
                                        macos_name = f"macOS 14 Sonoma"
                                    elif darwin_major == 22:
                                        macos_name = "macOS 13 Ventura"
                                    elif darwin_major == 21:
                                        macos_name = "macOS 12 Monterey"
                                    elif darwin_major == 20:
                                        macos_name = "macOS 11 Big Sur"
                                    elif darwin_major == 19:
                                        macos_name = "macOS 10.15 Catalina"
                                    elif darwin_major == 18:
                                        macos_name = "macOS 10.14 Mojave"
                                    elif darwin_major == 17:
                                        macos_name = "macOS 10.13 High Sierra"
                                    elif darwin_major == 16:
                                        macos_name = "macOS 10.12 Sierra"
                                    else:
                                        macos_name = f"macOS (Darwin {darwin_major})"
                                    
                                    # Extract architecture from banner
                                    if "X86_64" in banner_text or "x86_64" in banner_text:
                                        architecture = "x64"
                                    elif "ARM64" in banner_text or "arm64" in banner_text:
                                        architecture = "ARM64"
                                    else:
                                        architecture = "Unknown"
                                    
                                    os_version = f"{macos_name} (Darwin {darwin_ver})"
                                    logger.info(f"Mapped to: {os_version}, Architecture: {architecture}")
                                    
                            except (IndexError, ValueError) as e:
                                logger.warning(f"Could not parse Darwin version from banner: {e}")
                                os_version = banner_text
                        else:
                            logger.warning("No valid Darwin banner found in banners data")
                            
                except Exception as e:
                    logger.warning(f"Could not get banners data: {e}")
                
                # Try to get system info from mac.pslist
                pslist_data = self._run_volatility("mac.pslist.PsList")
                
                if pslist_data:
                    logger.info(f"Got pslist data for macOS system detection")
                
                # Extract usernames from process data - AGGRESSIVE APPROACH
                usernames_set = set()
                hostname_candidates = set()
                
                try:
                    with open(self.memory_json, "r") as f:
                        mem_data = json.load(f)
                        processes = mem_data.get("processes", [])
                        
                        logger.info(f"Checking {len(processes)} macOS processes for username extraction")
                        
                        # First pass: look for obvious user indicators
                        for proc in processes:
                            # Method 1: Process name might indicate user
                            proc_name = str(proc.get("ImageFileName", "") or proc.get("comm", "") or proc.get("COMM", "") or proc.get("NAME", ""))
                            
                            # User-specific processes
                            if any(app in proc_name.lower() for app in ["finder", "dock", "safari", "loginwindow", "windowserver"]):
                                logger.info(f"Found user process: {proc_name}")
                                
                                # Check all possible user fields
                                user_field = (proc.get("User") or proc.get("user") or 
                                            proc.get("UID") or proc.get("uid") or 
                                            proc.get("OWNER") or proc.get("owner"))
                                
                                if user_field:
                                    user_str = str(user_field)
                                    logger.info(f"  User field value: {user_str}")
                                    
                                    # Handle "user@hostname" format
                                    if "@" in user_str:
                                        username, host = user_str.split("@", 1)
                                        usernames_set.add(username)
                                        hostname_candidates.add(host)
                                        logger.info(f"  Extracted username: {username}, hostname: {host}")
                                    # Handle numeric UIDs (macOS user UIDs >= 501)
                                    elif user_str.isdigit():
                                        uid_num = int(user_str)
                                        if uid_num >= 501:
                                            # Use generic username based on UID
                                            usernames_set.add(f"user{uid_num}")
                                            logger.info(f"  Found user UID: {uid_num}")
                                    # Handle direct username
                                    elif user_str not in ["root", "daemon", "nobody", "_unknown", "0"]:
                                        usernames_set.add(user_str)
                                        logger.info(f"  Found username: {user_str}")
                            
                            # Method 2: Check PID/PPID patterns (user processes typically have higher PIDs)
                            pid = proc.get("PID") or proc.get("pid")
                            if pid and isinstance(pid, int) and pid > 100:
                                # These are likely user processes, not kernel
                                if "finder" in proc_name.lower() or "dock" in proc_name.lower():
                                    # Even if we don't have username, we know there's a user
                                    logger.info(f"Found user-context process (PID {pid}): {proc_name}")
                        
                        # Second pass: try to find hostname from network info
                        connections = mem_data.get("connections", [])
                        for conn in connections[:20]:  # Check first 20 connections
                            local_addr = str(conn.get("LocalAddr", ""))
                            if local_addr and not local_addr[0].isdigit() and local_addr not in ["localhost", "*", ""]:
                                hostname_candidates.add(local_addr.split(".")[0])
                                logger.info(f"Found hostname candidate from network: {local_addr}")
                        
                except Exception as e:
                    logger.warning(f"Could not extract macOS usernames from memory JSON: {e}")
                
                # If we found usernames, use them
                if usernames_set:
                    usernames_list = sorted(list(usernames_set))
                    logger.info(f"Successfully extracted {len(usernames_list)} username(s): {usernames_list}")
                else:
                    # Fallback: assume there's at least one user
                    usernames_list = ["macuser"]
                    logger.warning("No usernames extracted, using default 'macuser'")
                
                # Set hostname
                if hostname_candidates:
                    hostname = sorted(list(hostname_candidates))[0]
                    logger.info(f"Using hostname: {hostname}")
                else:
                    hostname = "Mac"
                    logger.warning("No hostname found, using default 'Mac'")
                
                # If OS version is still just "macOS", try to infer from process patterns
                if os_version == "macOS" and processes:
                    # Check for common macOS system processes to infer version
                    process_names = [str(p.get("ImageFileName", "") or p.get("comm", "")).lower() for p in processes]
                    
                    # macOS version hints based on process patterns
                    if "notificationcenter" in process_names or "controlcenter" in process_names:
                        os_version = "macOS 11+ (Big Sur or later)"
                    elif "spotlight" in process_names or "notifyd" in process_names:
                        os_version = "macOS 10.14+ (Mojave or later)"
                    else:
                        os_version = "macOS (version unknown)"
                
                logger.info(f"macOS extraction complete - hostname: {hostname}, users: {usernames_list}, os: {os_version}")
                
                self.analysis_results["system_info"] = {
                    "computer_name": hostname,
                    "hostname": hostname,
                    "os_version": os_version,
                    "usernames": usernames_list,
                    "plugin_output": [],
                    "architecture": architecture
                }
            
            # === FALLBACK FOR UNKNOWN OS ===
            else:
                logger.warning(f"Unknown OS type: {os_type}. Using fallback extraction.")
                self.analysis_results["system_info"] = {
                    "computer_name": "Unknown",
                    "hostname": "Unknown", 
                    "os_version": "Unknown",
                    "usernames": [],
                    "plugin_output": []
                }
    
    def analyze_processes(self):
        """Analyze process information from extraction JSON."""
        logger.info("Analyzing processes...")
        
        try:
            with open(self.memory_json) as f:
                data = json.load(f)
            
            processes = data.get("processes", [])
            
            # Basic stats
            process_names = [p.get("ImageFileName", "").lower() for p in processes if p.get("ImageFileName")]
            name_counts = Counter(process_names)
            
            # Find suspicious processes
            suspicious = []
            for proc in processes:
                score = proc.get("suspicious_score", 0)
                if score > 0:
                    suspicious.append({
                        "pid": proc.get("PID"),
                        "name": proc.get("ImageFileName"),
                        "score": score,
                        "tags": proc.get("tags", [])
                    })
            
            # Identify shell processes
            shells = [p for p in processes 
                    if p.get("ImageFileName", "").lower() in 
                    ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]]
            
            # Build results dictionary
            self.analysis_results["process_analysis"] = {
                "all_processes": processes,  # Store all processes for later use
                "total_processes": len(processes),
                "unique_process_names": len(name_counts),
                "most_common_processes": name_counts.most_common(10),
                "suspicious_processes": suspicious,
                "shell_processes": len(shells),
                "shell_details": [
                    {"pid": p.get("PID"), "name": p.get("ImageFileName")} 
                    for p in shells
                ]
            }
            
        except Exception as e:
            logger.error(f"Process analysis failed: {e}")
    
    def analyze_network(self):
        """Analyze network connections."""
        logger.info("Analyzing network connections...")
        
        try:
            with open(self.memory_json) as f:
                data = json.load(f)
            
            connections = data.get("connections", [])
            
            # External connections
            external = [c for c in connections 
                       if c.get("tags") and "external_destination" in c.get("tags", [])]
            
            # Listening ports
            listening = [c for c in connections 
                        if c.get("State", "").upper() == "LISTENING"]
            
            # Established connections
            established = [c for c in connections 
                          if c.get("State", "").upper() == "ESTABLISHED"]
            
            # Suspicious connections
            suspicious = [c for c in connections 
                         if c.get("suspicious_score", 0) > 0]
            
            # Get unique remote IPs
            remote_ips = list(set([
                c.get("ForeignAddr") 
                for c in connections 
                if c.get("ForeignAddr") and c.get("ForeignAddr") not in ("0.0.0.0", "*")
            ]))
            
            # Get unique local ports
            local_ports = list(set([
                c.get("LocalPort") 
                for c in connections 
                if c.get("LocalPort")
            ]))
            
            self.analysis_results["network_analysis"] = {
                "total_connections": len(connections),
                "external_connections": len(external),
                "listening_ports": len(listening),
                "established_connections": len(established),
                "suspicious_connections": len(suspicious),
                "unique_remote_ips": len(remote_ips),
                "unique_local_ports": len(local_ports),
                "listening_port_details": [
                    {"port": c.get("LocalPort"), "proto": c.get("Proto")} 
                    for c in listening
                ],
                "external_connection_details": [
                    {
                        "remote_ip": c.get("ForeignAddr"),
                        "remote_port": c.get("ForeignPort"),
                        "local_port": c.get("LocalPort"),
                        "state": c.get("State")
                    }
                    for c in external[:10]  # Top 10 only
                ],
                "suspicious_connection_details": suspicious
            }
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
    
    def analyze_files(self):
        """Analyze file artifacts."""
        logger.info("Analyzing file artifacts...")
        
        try:
            with open(self.file_json) as f:
                data = json.load(f)
            
            file_objects = data.get("file_objects", [])
            file_handles = data.get("file_handles", [])
            
            # Analyze file extensions
            file_extensions = []
            for obj in file_objects:
                if isinstance(obj, dict):
                    filename = obj.get("FileName", "")
                    if "." in filename:
                        ext = filename.split(".")[-1].lower()
                        file_extensions.append(ext)
            
            ext_counts = Counter(file_extensions)
            
            # Find executable files
            executables = [
                obj for obj in file_objects 
                if isinstance(obj, dict) and 
                obj.get("FileName", "").lower().endswith((".exe", ".dll", ".sys"))
            ]
            
            # Find suspicious file locations
            suspicious_paths = [
                obj for obj in file_objects
                if isinstance(obj, dict) and any(
                    path in obj.get("FileName", "").lower()
                    for path in ["temp", "appdata", "download"]
                )
            ]
            
            self.analysis_results["file_analysis"] = {
                "total_file_objects": len(file_objects),
                "total_file_handles": len(file_handles),
                "unique_extensions": len(ext_counts),
                "most_common_extensions": ext_counts.most_common(10),
                "executable_files": len(executables),
                "suspicious_locations": len(suspicious_paths),
                "suspicious_location_details": [
                    obj.get("FileName") for obj in suspicious_paths[:20]
                ]
            }
            
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
    
    def analyze_registry(self):
        """Analyze registry artifacts."""
        logger.info("Analyzing registry artifacts...")
        
        try:
            with open(self.file_json) as f:
                data = json.load(f)
            
            registry = data.get("registry_activity", {})
            hives = registry.get("hives", [])
            user_assist = registry.get("user_assist", [])
            
            # Analyze UserAssist for program execution
            if user_assist and isinstance(user_assist, list):
                executed_programs = [
                    entry.get("Name", "") 
                    for entry in user_assist 
                    if isinstance(entry, dict)
                ]
            else:
                executed_programs = []
            
            self.analysis_results["registry_analysis"] = {
                "total_hives": len(hives) if hives else 0,
                "user_assist_entries": len(user_assist) if user_assist else 0,
                "recently_executed_programs": len(executed_programs),
                "executed_program_details": executed_programs[:20]  # Top 20
            }
            
        except Exception as e:
            logger.error(f"Registry analysis failed: {e}")
    
    def identify_suspicious_findings(self):
        """Identify and summarize suspicious findings."""
        logger.info("Identifying suspicious findings...")
        
        findings = []
        
        # Check for suspicious processes
        susp_procs = self.analysis_results["process_analysis"].get("suspicious_processes", [])
        if susp_procs:
            findings.append({
                "category": "Processes",
                "severity": "HIGH" if any(p["score"] > 5 for p in susp_procs) else "MEDIUM",
                "finding": f"Found {len(susp_procs)} suspicious process(es)",
                "details": susp_procs
            })
        
        # Check for suspicious network connections
        susp_conns = self.analysis_results["network_analysis"].get("suspicious_connections", 0)
        if susp_conns > 0:
            conn_details = self.analysis_results["network_analysis"].get("suspicious_connection_details", [])
            findings.append({
                "category": "Network",
                "severity": "HIGH" if susp_conns > 5 else "MEDIUM",
                "finding": f"Found {susp_conns} suspicious network connection(s)",
                "details": conn_details
            })
        
        # Check for external connections
        ext_conns = self.analysis_results["network_analysis"].get("external_connections", 0)
        if ext_conns > 10:
            findings.append({
                "category": "Network",
                "severity": "LOW",
                "finding": f"System has {ext_conns} external network connections",
                "details": self.analysis_results["network_analysis"].get("external_connection_details", [])
            })
        
        # Check for shell processes
        shells = self.analysis_results["process_analysis"].get("shell_processes", 0)
        if shells > 5:
            findings.append({
                "category": "Processes",
                "severity": "MEDIUM",
                "finding": f"Found {shells} shell/scripting processes",
                "details": self.analysis_results["process_analysis"].get("shell_details", [])
            })
        
        self.analysis_results["suspicious_findings"] = findings

    def calculate_risk_score(self) -> int:
        """Calculate overall risk score 0-100"""
        score = 0
        
        threats = self.analysis_results.get("suspicious_findings", [])
        high = len([f for f in threats if f["severity"] == "HIGH"])
        medium = len([f for f in threats if f["severity"] == "MEDIUM"])
        
        score += high * 30
        score += medium * 15
        
        return min(score, 100)
    
    def generate_summary(self):
        """Generate executive summary."""
        logger.info("Generating summary...")

        # Start from whatever analyze_system_info() already collected
        sys_info = self.analysis_results.get("system_info", {}).copy()

        # 1. Computer name
        computer_name = sys_info.get("computer_name", "Unknown")

        # 2. Primary username (filter out system / machine accounts)
        users = sys_info.get("usernames", [])
        system_accounts = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

        real_users = [
            u for u in users
            if u and not u.endswith("$") and u not in system_accounts
        ]
        primary_user = real_users[0] if real_users else "Unknown"

        # 3. OS Version + architecture from memory_enriched.json
        try:
            with open(self.memory_json, "r") as f:
                mem = json.load(f)

            os_type = mem.get("os_type", "Unknown")
            build = mem.get("build_number") or mem.get("BuildNumber")
            architecture = mem.get("architecture", "Unknown")

            if os_type != "Unknown" and build:
                os_version = f"{os_type} (Build {build})"
            else:
                os_version = os_type
        except Exception:
            os_version = "Unknown"
            architecture = "Unknown"

        sys_info["username"] = primary_user
        sys_info["computer_name"] = computer_name
        sys_info["os_version"] = os_version
        sys_info["architecture"] = architecture
        sys_info["usernames"] = users  # keep full list

        self.analysis_results["system_info"] = sys_info

        summary = {
            "analysis_timestamp": self.analysis_results["timestamp"],
            "risk_score": self.calculate_risk_score(),
            "system": {
                "computer_name": self.analysis_results["system_info"].get("computer_name", "Unknown"),
                "users": self.analysis_results["system_info"].get("usernames", [])
            },
            "processes": {
                "total": self.analysis_results["process_analysis"].get("total_processes", 0),
                "suspicious": len(self.analysis_results["process_analysis"].get("suspicious_processes", [])),
                "shells": self.analysis_results["process_analysis"].get("shell_processes", 0)
            },
            "network": {
                "total_connections": self.analysis_results["network_analysis"].get("total_connections", 0),
                "external": self.analysis_results["network_analysis"].get("external_connections", 0),
                "listening_ports": self.analysis_results["network_analysis"].get("listening_ports", 0),
                "suspicious": self.analysis_results["network_analysis"].get("suspicious_connections", 0)
            },
            "files": {
                "total_objects": self.analysis_results["file_analysis"].get("total_file_objects", 0),
                "executables": self.analysis_results["file_analysis"].get("executable_files", 0),
                "suspicious_locations": self.analysis_results["file_analysis"].get("suspicious_locations", 0)
            },
            "threats": {
                "total_findings": len(self.analysis_results["suspicious_findings"]),
                "high_severity": len([f for f in self.analysis_results["suspicious_findings"] if f["severity"] == "HIGH"]),
                "medium_severity": len([f for f in self.analysis_results["suspicious_findings"] if f["severity"] == "MEDIUM"]),
                "low_severity": len([f for f in self.analysis_results["suspicious_findings"] if f["severity"] == "LOW"])
            }
        }

        # add MITRE techniques into the summary
        suspicious_procs = self.analysis_results["process_analysis"].get("suspicious_processes", [])
        mitre_hits = sorted(list({
            MITRE_MAP.get(p.get("name", "").lower())
            for p in suspicious_procs
            if p.get("name", "").lower() in MITRE_MAP
        }))
        # keep only non-None strings
        summary["threats"]["mitre_techniques"] = [h for h in mitre_hits if h]

        self.analysis_results["summary"] = summary

    
    def run_analysis(self) -> Dict[str, Any]:
        """Run complete automated analysis."""
        logger.info("Starting automated analysis...")
        
        self.analyze_system_info()
        self.analyze_processes()
        self.analyze_network()
        self.analyze_files()
        self.analyze_registry()
        self.identify_suspicious_findings()
        self.generate_summary()
        
        logger.info("Automated analysis complete")
        return self.analysis_results


def generate_text_report(analysis: Dict[str, Any]) -> str:
    """Generate human-readable text report."""
    report = []
    report.append("="*80)
    report.append("VAST AUTOMATED FORENSIC ANALYSIS REPORT")
    report.append("="*80)
    report.append("")

    # Add timestamp
    timestamp = analysis.get("timestamp", "Unknown")
    report.append(f"Generated: {timestamp}")
    report.append("")
    
    # System Information
    report.append("SYSTEM INFORMATION")
    report.append("-"*80)
    summary = analysis.get("summary", {})
    risk_score = summary.get("risk_score", 0)
    report.append(f"Overall Risk Score: {risk_score}/100")
    system = summary.get("system", {})
    report.append(f"Computer Name: {system.get('computer_name', 'Unknown')}")
    
    # Show unique users only
    users = system.get('users', [])
    unique_users = sorted(set(users))[:10]  # Top 10 unique users
    report.append(f"Unique Users: {', '.join(unique_users) if unique_users else 'None'}")
    report.append("")

    report.append("KEY INDICATORS")
    report.append("-"*80)
    procs = summary.get("processes", {})
    net = summary.get("network", {})
    threats = summary.get("threats", {})

    report.append(f"Suspicious Processes: {procs.get('suspicious', 0)}")
    report.append(f"Active External Connections: {net.get('external', 0)}")
    report.append(f"High Severity Findings: {threats.get('high_severity', 0)}")
    report.append("")
    
    # Executive Summary
    report.append("EXECUTIVE SUMMARY")
    report.append("-"*80)
    procs = summary.get("processes", {})
    report.append(f"Total Processes: {procs.get('total', 0)}")
    report.append(f"Suspicious Processes: {procs.get('suspicious', 0)}")
    report.append(f"Shell/Script Processes: {procs.get('shells', 0)}")
    report.append("")
    
    net = summary.get("network", {})
    report.append(f"Total Network Connections: {net.get('total_connections', 0)}")
    report.append(f"External Connections: {net.get('external', 0)}")
    report.append(f"Listening Ports: {net.get('listening_ports', 0)}")
    report.append(f"Suspicious Connections: {net.get('suspicious', 0)}")
    report.append("")
    
    files = summary.get("files", {})
    report.append(f"Total File Objects: {files.get('total_objects', 0)}")
    report.append(f"Executable Files: {files.get('executables', 0)}")
    report.append(f"Suspicious File Locations: {files.get('suspicious_locations', 0)}")
    report.append("")
    
    # Threat Assessment
    threats = summary.get("threats", {})
    report.append("THREAT ASSESSMENT")
    report.append("-"*80)
    report.append(f"Total Findings: {threats.get('total_findings', 0)}")
    report.append(f"  HIGH Severity: {threats.get('high_severity', 0)}")
    report.append(f"  MEDIUM Severity: {threats.get('medium_severity', 0)}")
    report.append(f"  LOW Severity: {threats.get('low_severity', 0)}")
    report.append("")

    # Extract red flags and anomalies from analysis
    processes = analysis.get("process_analysis", {}).get("suspicious_processes", [])
    all_procs = analysis.get("process_analysis", {}).get("all_processes", [])
    if not all_procs:
        # Fallback to using processes from memory_json
        all_procs = []
    conns = analysis.get("network_analysis", {}).get("suspicious_connection_details", [])
    file_objs = analysis.get("file_analysis", {}).get("suspicious_location_details", [])

    # Call your detection functions
    red_flags = detect_process_red_flags(all_procs)
    net_anomalies = detect_network_anomalies(conns)
    persistence = detect_persistence(file_objs)

    # MITRE hits
    mitre_hits = list({
        MITRE_MAP.get(p.get("name").lower())
        for p in processes
        if p.get("name", "").lower() in MITRE_MAP
    })
    
    report.append("\nMITRE ATT&CK TECHNIQUES OBSERVED")
    report.append("-" * 80)
    if mitre_hits:
        for h in mitre_hits:
            report.append(f"  {h}")
    else:
        report.append("  None detected")

    report.append("\nPROCESS RED FLAGS")
    report.append("-" * 80)
    if red_flags:
        for r in red_flags:
            report.append(f"  {r}")
    else:
        report.append("  None detected")

    report.append("\nNETWORK ANOMALIES")
    report.append("-" * 80)
    if net_anomalies:
        for n in net_anomalies:
            report.append(f"  {n}")
    else:
        report.append("  None detected")

    report.append("\nPERSISTENCE INDICATORS")
    report.append("-" * 80)
    if persistence:
        for p in persistence:
            report.append(f"  {p}")
    else:
        report.append("  None detected")



    # Detailed Findings
    findings = analysis.get("suspicious_findings", [])
    if findings:
        report.append("DETAILED FINDINGS")
        report.append("-"*80)
        for i, finding in enumerate(findings, 1):
            report.append(f"{i}. [{finding['severity']}] {finding['category']}: {finding['finding']}")
        report.append("")
    
    # Most Common Processes
    proc_analysis = analysis.get("process_analysis", {})
    common_procs = proc_analysis.get("most_common_processes", [])
    if common_procs:
        report.append("MOST COMMON PROCESSES")
        report.append("-"*80)
        for name, count in common_procs[:10]:
            report.append(f"  {name}: {count} instance(s)")
        report.append("")
    
    # Listening Ports
    net_analysis = analysis.get("network_analysis", {})
    listening = net_analysis.get("listening_port_details", [])
    if listening:
        report.append("LISTENING PORTS")
        report.append("-"*80)
        for port_info in listening[:15]:
            report.append(f"  Port {port_info['port']}/{port_info['proto']}")
        report.append("")
    
    # File Extensions
    file_analysis = analysis.get("file_analysis", {})
    extensions = file_analysis.get("most_common_extensions", [])
    if extensions:
        report.append("MOST COMMON FILE EXTENSIONS")
        report.append("-"*80)
        for ext, count in extensions[:10]:
            report.append(f"  .{ext}: {count} file(s)")
        report.append("")
    
    report.append("RECOMMENDATIONS")
    report.append("-"*80)
    
    threats = summary.get("threats", {})
    procs = summary.get("processes", {})
    net = summary.get("network", {})
    
    if threats.get('high_severity', 0) > 0:
        report.append("  [!] Immediate action required - high severity threats detected")
    if procs.get('suspicious', 0) > 5:
        report.append("  [!] Review suspicious processes for malware")
    if net.get('external', 0) > 10:
        report.append("  [!] Investigate external network connections")
    if threats.get('total_findings', 0) == 0:
        report.append("  [OK] No immediate threats detected")

    report.append("")
    
    report.append("="*80)
    report.append("END OF REPORT")
    report.append("="*80)
    
    return "\n".join(report)


def main(argv: List[str]) -> int:
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Automated forensic analysis for VAST extractions"
    )
    parser.add_argument(
        "raw_file",
        help="Path to raw memory dump"
    )
    parser.add_argument(
        "memory_json",
        help="Path to memory extraction JSON"
    )
    parser.add_argument(
        "file_json",
        help="Path to file extraction JSON"
    )
    parser.add_argument(
        "--os",
        default="windows",
        help="Operating system type (windows/linux/macos)"  # ← ADD THIS
    )
    parser.add_argument(
        "--vol-path",
        help="Path to Volatility vol.py",
        default=None
    )
    parser.add_argument(
        "--output",
        help="Output path for analysis JSON",
        default=None
    )
    parser.add_argument(
        "--text-report",
        help="Output path for text report",
        default=None
    )
    parser.add_argument(
        "--session",
        help="Session directory (for integration with vast.py)"
    )
    
    args = parser.parse_args(argv)
    
    analyzer = AutomatedAnalyzer(
        raw_path=args.raw_file,
        memory_json=args.memory_json,
        file_json=args.file_json,
        vol_script=args.vol_path
    )
    
    analysis = analyzer.run_analysis()
    
    # Determine output paths
    if args.output:
        json_out = Path(args.output)
    else:
        if args.session:
            output_dir = Path(args.session) / "reports"
        else:
            output_dir = get_script_dir() / "output" / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        json_out = output_dir / "automated_analysis.json"
    
    # Save JSON analysis
    with open(json_out, 'w') as f:
        json.dump(analysis, f, indent=2)
    print(f"Analysis JSON saved to: {json_out}")
    
    # Generate and save text report
    text_report = generate_text_report(analysis)
    
    if args.text_report:
        text_out = Path(args.text_report)
    else:
        text_out = json_out.with_suffix('.txt')
    
    text_out.write_text(text_report, encoding='utf-8')
    print(f"Text report saved to: {text_out}")
    
    # Print report to console
    print("\n" + text_report)
    
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))