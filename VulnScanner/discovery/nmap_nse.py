# Vuln Hunter - Nmap with NSE Scripts
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
import asyncio
import nmap
from typing import Dict

class NmapScanner:
    def __init__(self, timeout: int = 600):
        self.nm = nmap.PortScanner()
        self.timeout = timeout

    async def run_scan(self, target: str, arguments: str = "-sV --script=vuln") -> Dict:
        """
        Run nmap scan with NSE scripts.
        
        Args:
            target: IP address or hostname
            arguments: Nmap arguments (default: '-sV --script=vuln')
        
        Returns:
            Dictionary with scan results
        """
        try:
            def sync_scan():
                return self.nm.scan(hosts=target, arguments=arguments, timeout=self.timeout * 1000)
            
            return await asyncio.wait_for(
                asyncio.to_thread(sync_scan),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            raise Exception(f"Nmap scan timed out after {self.timeout} seconds")
        except Exception as e:
            raise Exception(f"Nmap scan failed: {str(e)}")

async def run_nmap_nse(target: str, scripts: str = "vuln", timeout: int = 600) -> Dict:
    """
    Wrapper for NmapScanner with default vulnerability scripts.
    
    Args:
        target: IP address or hostname
        scripts: NSE script category or list (default: 'vuln')
        timeout: Maximum execution time in seconds (default: 600)
    
    Returns:
        Dictionary with scan results
    """
    scanner = NmapScanner(timeout=timeout)
    return await scanner.run_scan(target, f"-sV --script={scripts}")