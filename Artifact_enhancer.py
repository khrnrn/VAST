#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set


def is_private_ip(ip: str) -> bool:
    """Very simple RFC1918/localhost check."""
    try:
        if ip.startswith(("10.", "127.", "0.", "169.254.")):
            return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) > 1 and parts[1].isdigit():
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
        if ip in ("::1", "::", ""):
            return True
    except Exception:
        return False
    return False


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def process_identity(proc: Dict[str, Any]) -> Tuple[str, Any]:
    """
    Identity for comparing processes between baseline and current.
    We ignore PID (changes every boot); we use (ImageFileName, SessionId).
    """
    name = str(proc.get("ImageFileName", "")).lower()
    session = proc.get("SessionId")
    return (name, session)


def conn_identity(conn: Dict[str, Any]) -> Tuple[Any, ...]:
    """
    Identity for comparing connections between baseline and current.
    """
    return (
        conn.get("Proto"),
        conn.get("LocalAddr"),
        conn.get("LocalPort"),
        conn.get("ForeignAddr"),
        conn.get("ForeignPort"),
    )


def score_process(proc: Dict[str, Any], iocs: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    tags: List[str] = []

    name_raw = str(proc.get("ImageFileName", "")).strip()
    name = name_raw.lower()

    suspicious_proc_names = {n.lower() for n in iocs.get("malicious_process_names", [])}
    high_risk_substrings = [s.lower() for s in iocs.get("high_risk_process_substrings", [])]

    # Exact known-bad name
    if name in suspicious_proc_names:
        score += 8
        tags.append("known_malicious_name")

    # Names containing "rat", "mimikatz", "miner", etc.
    for sub in high_risk_substrings:
        if sub and sub in name:
            score += 3
            tags.append("suspicious_name_pattern")
            break

    # Generic “high-risk” tools
    risky_tools = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    if name in risky_tools:
        score += 3
        tags.append("script_or_shell")

    # Wow64 (32-bit on 64-bit OS)
    wow64 = proc.get("Wow64")
    if isinstance(wow64, bool) and wow64:
        score += 1
        tags.append("wow64_process")

    # Very high thread count
    threads = proc.get("Threads")
    if isinstance(threads, int) and threads >= 50:
        score += 2
        tags.append("high_thread_count")

    # IOC process name hit
    if name in {n.lower() for n in iocs.get("ioc_process_names", [])}:
        score += 10
        tags.append("ioc_process_hit")

    return score, sorted(set(tags))


def score_connection(conn: Dict[str, Any], iocs: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    tags: List[str] = []

    proto = str(conn.get("Proto", "")).upper()
    state = str(conn.get("State", "")).upper()
    laddr = str(conn.get("LocalAddr", ""))
    faddr = str(conn.get("ForeignAddr", ""))
    lport = conn.get("LocalPort")
    fport = conn.get("ForeignPort")

    malicious_ips = set(iocs.get("malicious_ips", []))
    suspicious_ports = set(iocs.get("suspicious_ports", []))

    # Listening sockets
    if state == "LISTENING":
        tags.append("listening")

    # Sensitive local ports (RDP, SMB, WinRM, etc.)
    if isinstance(lport, int) and lport in {22, 23, 80, 443, 445, 3389, 5985, 5986}:
        tags.append("sensitive_local_port")
        score += 2

    # Suspicious remote ports (C2 style)
    if isinstance(fport, int) and fport in suspicious_ports:
        tags.append("suspicious_remote_port")
        score += 3

    # External connections out of LAN
    if faddr and faddr not in ("0.0.0.0", "*") and not is_private_ip(faddr):
        tags.append("external_destination")
        score += 2

    # IOC IP hit
    if faddr in malicious_ips:
        tags.append("ioc_ip_hit")
        score += 10

    # Active TCP session
    if proto.startswith("TCP") and state == "ESTABLISHED":
        tags.append("active_tcp_session")
        score += 1

    return score, sorted(set(tags))


def enrich(
    current: Dict[str, Any],
    baseline: Dict[str, Any] = None,
    iocs: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Enriches the extractor JSON with:
      - suspicious_score + tags per process/connection
      - optional baseline diff
      - IOC hits summary
    """
    if iocs is None:
        iocs = {
            "malicious_process_names": [],
            "high_risk_process_substrings": ["mimikatz", "rat", "miner", "hacktool"],
            "ioc_process_names": [],
            "malicious_ips": [],
            "suspicious_ports": [4444, 1337, 8081],
        }

    # ----- per-process enrichment -----
    processes = current.get("processes", [])
    for p in processes:
        s, t = score_process(p, iocs)
        p["suspicious_score"] = s
        p["tags"] = t

    # ----- per-connection enrichment -----
    connections = current.get("connections", [])
    for c in connections:
        s, t = score_connection(c, iocs)
        c["suspicious_score"] = s
        c["tags"] = t

    # ----- baseline diff (optional) -----
    diff: Dict[str, Any] = {}
    if baseline is not None:
        base_procs = baseline.get("processes", [])
        base_conns = baseline.get("connections", [])

        base_proc_ids: Set[Tuple[str, Any]] = {process_identity(p) for p in base_procs}
        curr_proc_ids: Set[Tuple[str, Any]] = {process_identity(p) for p in processes}

        new_proc_ids = curr_proc_ids - base_proc_ids
        terminated_proc_ids = base_proc_ids - curr_proc_ids

        diff["new_processes"] = [
            p for p in processes if process_identity(p) in new_proc_ids
        ]
        diff["terminated_processes"] = [
            p for p in base_procs if process_identity(p) in terminated_proc_ids
        ]

        base_conn_ids: Set[Tuple[Any, ...]] = {conn_identity(c) for c in base_conns}
        curr_conn_ids: Set[Tuple[Any, ...]] = {conn_identity(c) for c in connections}

        new_conn_ids = curr_conn_ids - base_conn_ids
        terminated_conn_ids = base_conn_ids - curr_conn_ids

        diff["new_connections"] = [
            c for c in connections if conn_identity(c) in new_conn_ids
        ]
        diff["terminated_connections"] = [
            c for c in base_conns if conn_identity(c) in terminated_conn_ids
        ]

        base_ips = {c.get("ForeignAddr") for c in base_conns}
        curr_ips = {c.get("ForeignAddr") for c in connections}
        new_ips = {ip for ip in curr_ips - base_ips if ip}

        diff["new_remote_ips"] = sorted(new_ips)

    if diff:
        current["diff"] = diff

    # ----- IOC hits summary (top-level) -----
    ioc_hits = {
        "processes": [
            p for p in processes if any(t.startswith("ioc_") for t in p.get("tags", []))
        ],
        "connections": [
            c for c in connections if any(t.startswith("ioc_") for t in c.get("tags", []))
        ],
    }
    current["ioc_hits"] = ioc_hits

    return current


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=(
            "Enrich memory extraction JSON with suspicious scores, tags, "
            "baseline diff, and IOC hits."
        )
    )
    parser.add_argument(
        "current",
        help="Path to current extraction JSON (output from your memory extractor).",
    )
    parser.add_argument(
        "--baseline",
        help="Optional baseline extraction JSON for diff.",
        default=None,
    )
    parser.add_argument(
        "--ioc",
        help="Optional IOC configuration JSON.",
        default=None,
    )
    parser.add_argument(
        "--output",
        help=(
            "Output JSON path. If not set, a default '<current_stem>_enriched.json' "
            "will be created next to the current JSON."
        ),
        default=None,
    )

    args = parser.parse_args(argv)

    curr_path = Path(args.current).resolve()
    cur_data = load_json(curr_path)

    baseline_data = None
    if args.baseline:
        baseline_path = Path(args.baseline).resolve()
        baseline_data = load_json(baseline_path)

    ioc_conf = None
    if args.ioc:
        ioc_conf = load_json(Path(args.ioc).resolve())

    enriched_data = enrich(cur_data, baseline=baseline_data, iocs=ioc_conf)

    out_text = json.dumps(enriched_data, indent=2)

    # Auto-generate output filename if not provided
    if args.output:
        out_path = Path(args.output).resolve()
    else:
        out_path = curr_path.with_name(curr_path.stem + "_enriched.json")

    out_path.write_text(out_text, encoding="utf-8")
    print(f"Enriched result written to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
