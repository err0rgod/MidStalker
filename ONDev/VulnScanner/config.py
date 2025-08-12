
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
RESULTS_DIR = DATA_DIR / "results"
REPORTS_DIR = DATA_DIR / "reports"
EXPLOITS_DIR = DATA_DIR / "exploits"

# Tools configuration (paths or commands)
NMAP_CMD = os.getenv("NMAP_CMD", "nmap")
MASSCAN_CMD = os.getenv("MASSCAN_CMD", "masscan")
SEARCHSPLOIT_CMD = os.getenv("SEARCHSPLOIT_CMD", "searchsploit")

# Operational config
CONCURRENT_TASKS = int(os.getenv("CONCURRENT_TASKS", "10"))
DEFAULT_TARGET = os.getenv("DEFAULT_TARGET", "192.168.0.0/24")

# Safety flags
ALLOW_EXPLOIT_EXECUTION = False  # Must be switched on manually and with explicit consent

# Ensure directories exist
for d in (DATA_DIR, RAW_DIR, RESULTS_DIR, REPORTS_DIR, EXPLOITS_DIR):
    d.mkdir(parents=True, exist_ok=True)