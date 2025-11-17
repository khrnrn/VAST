# parser.py
import os
import sys
import shutil
import logging
from pathlib import Path
from datetime import datetime

# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_script_dir() -> Path:
    """Get the directory where this script is located."""
    return Path(__file__).resolve().parent


def generate_output_path(input_path: Path) -> Path:
    """
    Generate a unique output path in the script's directory.
    Format: snapshot_YYYYMMDD_HHMMSS_XXXXXX.raw
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"snapshot_{timestamp}"
    output_dir = get_script_dir()

    # Avoid collision: add counter if needed
    counter = 0
    while True:
        suffix = f"_{counter:03d}" if counter > 0 else ""
        candidate = output_dir / f"{stem}{suffix}.raw"
        if not candidate.exists():
            return candidate
        counter += 1


def parse_snapshot(file_path: str) -> dict:
    """
    Parse VMware (.vmem) or VirtualBox (.sav) snapshot into raw memory dump.
    Output .raw file is saved in the same folder as parser.py.

    Args:
        file_path (str): Path to .vmem or .sav file

    Returns:
        dict: Result with keys:
            - success (bool)
            - input_file (str)
            - format (str)
            - output_raw (str): path to normalized raw memory file
            - size_bytes (int)
            - warnings (list)
    """
    result = {
        "success": False,
        "input_file": str(file_path),
        "format": "unknown",
        "output_raw": "",
        "size_bytes": 0,
        "warnings": [],
    }

    file_path = Path(file_path).resolve()

    if not file_path.exists():
        result["warnings"].append("File not found")
        return result

    if file_path.suffix.lower() == ".vmem":
        result["format"] = "vmware"
        return _handle_vmem(file_path, result)

    elif file_path.suffix.lower() == ".sav":
        result["format"] = "virtualbox"
        return _handle_sav(file_path, result)

    else:
        result["warnings"].append(f"Unsupported file extension: {file_path.suffix}")
        return result


def _handle_vmem(file_path: Path, result: dict) -> dict:
    """VMware .vmem is already a raw memory dump. Copy to project folder."""
    try:
        size = file_path.stat().st_size
        if size == 0:
            result["warnings"].append("File is empty")
            return result

        output_path = generate_output_path(file_path)
        shutil.copyfile(file_path, output_path)
        result["output_raw"] = str(output_path)

        result["size_bytes"] = size
        result["success"] = True
        logger.info(f"VMware .vmem parsed: {size} bytes → {result['output_raw']}")
        return result

    except Exception as e:
        result["warnings"].append(f"VMware parsing failed: {str(e)}")
        return result


def _handle_sav(file_path: Path, result: dict) -> dict:
    """
    Handle VirtualBox .sav file.
    For simplicity, copy as-is to project folder with warning.
    """
    try:
        size = file_path.stat().st_size
        if size == 0:
            result["warnings"].append("File is empty")
            return result

        result["warnings"].append(
            "VirtualBox .sav parsing is limited. Memory may be unparsed or compressed. "
            "For best results, convert .sav to raw memory using VBoxManage first."
        )

        output_path = generate_output_path(file_path)
        shutil.copyfile(file_path, output_path)
        result["output_raw"] = str(output_path)

        result["size_bytes"] = size
        result["success"] = True
        logger.info(f"VirtualBox .sav treated as raw (heuristic): {size} bytes → {result['output_raw']}")
        return result

    except Exception as e:
        result["warnings"].append(f"VirtualBox parsing failed: {str(e)}")
        return result


# CLI for testing
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parser.py <snapshot.vmem|.sav>")
        sys.exit(1)

    result = parse_snapshot(sys.argv[1])
    print("\n=== Parser Result ===")
    for k, v in result.items():
        print(f"{k}: {v}")
    if result["success"]:
        print(f"\n✅ Raw memory dumped to: {result['output_raw']}")
    else:
        print(f"\n❌ Failed: {result['warnings']}")