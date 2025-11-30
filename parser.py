import sys
import shutil
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_script_dir() -> Path:
    return Path(__file__).resolve().parent


def generate_base_output_path(session_dir: Path) -> Path:
    """Generate base name (without extension) for the session's copied files."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = session_dir / "raw"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"snapshot_{timestamp}"


def parse_snapshot(input_files: list[Path], session_dir: Path) -> dict:
    result = {
        "success": False,
        "input_files": [str(f) for f in input_files],
        "output_files": [],
        "size_bytes": 0,
        "warnings": [],
    }

    # Find .vmem (required)
    vmem_file = None
    vmsn_file = None
    for f in input_files:
        if f.suffix.lower() == ".vmem":
            vmem_file = f
        elif f.suffix.lower() in (".vmsn", ".vmss"):
            vmsn_file = f

    if not vmem_file or not vmem_file.exists():
        result["warnings"].append("Required .vmem file not found")
        return result

    base_output = generate_base_output_path(session_dir)

    try:
        # Copy .vmem
        vmem_dest = base_output.with_suffix(".vmem")
        shutil.copy2(vmem_file, vmem_dest)
        result["output_files"].append(str(vmem_dest))
        result["size_bytes"] = vmem_dest.stat().st_size

        # Copy .vmsn/.vmss if provided
        if vmsn_file and vmsn_file.exists():
            vmsn_dest = base_output.with_suffix(vmsn_file.suffix.lower())
            shutil.copy2(vmsn_file, vmsn_dest)
            result["output_files"].append(str(vmsn_dest))
            logger.info(f"Copied .vmsn to session: {vmsn_dest}")
        else:
            result["warnings"].append("No .vmsn/.vmss file provided — Volatility may not reconstruct memory correctly for Linux")

        result["success"] = True
        logger.info(f"VMware snapshot parsed: {vmem_file} → {base_output}.vmem (and .vmsn if present)")
        return result

    except Exception as e:
        result["warnings"].append(f"Snapshot parsing failed: {str(e)}")
        return result


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshots", nargs="+", help="VM snapshot files (.vmem and/or .vmsn/.vmss)")
    parser.add_argument("--session", required=True, help="Session folder from vast.py")
    args = parser.parse_args()

    session_dir = Path(args.session).resolve()
    input_files = [Path(f).resolve() for f in args.snapshots]

    result = parse_snapshot(input_files, session_dir)

    print("\n=== Parser Result ===")
    for k, v in result.items():
        print(f"{k}: {v}")

    if result["success"]:
        vmem_output = next((f for f in result["output_files"] if f.endswith(".vmem")), None)
        print(f"\n[SUCCESS] Memory dump ready at: {vmem_output}")
    else:
        print(f"\n[FAILED] {result['warnings']}")
        sys.exit(1)


if __name__ == "__main__":
    main()