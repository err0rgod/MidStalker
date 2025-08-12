import subprocess
from config import NMAP_CMD, RAW_DIR


def run(target: str) -> str:
    out_file = RAW_DIR / f"nmap_{target.replace('/', '_')}.xml"
    args = [NMAP_CMD, "-sV", "--script=default,safe", "-oX", str(out_file), target]
    subprocess.run(args, check=False)
    try:
        return out_file.read_text()
    except Exception:
        return