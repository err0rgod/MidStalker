# Vuln Hunter - Nmap with NSE Scripts
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
import asyncio
import nmap3
from typing import Dict

async def run_nmap_nse(target: str, scripts: str = "vuln") -> Dict:
    """
    Run nmap with NSE scripts for vulnerability detection.
    
    Args:
        target: IP address or hostname
        scripts: NSE script category or list (default: 'vuln')
    
    Returns:
        Dictionary with scan results
    """
    nmap = nmap3.Nmap()
    try:
        results = await asyncio.to_thread(
            nmap.nmap_version_detection,
            target,
            args=f"-sV --script={scripts}"
        )
        return results
    except Exception as e:
        raise Exception(f"Nmap NSE scan failed: {str(e)}")