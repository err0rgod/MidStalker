# Vuln Hunter - Results Parser
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
from typing import Dict, List, Any
import json

def normalize_results(scan_type: str, raw_results: Dict) -> List[Dict[str, Any]]:
    """
    Normalize different scanner outputs into common JSON schema.
    
    Args:
        scan_type: Type of scan (masscan, nmap, etc.)
        raw_results: Raw results from scanner
    
    Returns:
        List of normalized vulnerability records
    """
    normalized = []
    
    if scan_type == "masscan":
        for host in raw_results.get("hosts", []):
            for port in host.get("ports", []):
                normalized.append({
                    "ip": host["ip"],
                    "port": port["port"],
                    "protocol": port["proto"],
                    "service": "unknown",
                    "vulnerabilities": []
                })
    
    elif scan_type == "nmap":
        for host, data in raw_results.items():
            if host == "runtime" or host == "stats":
                continue
                
            for port in data.get("ports", []):
                vulns = []
                for script in port.get("scripts", []):
                    if "vuln" in script or "CVE" in script:
                        vulns.append({
                            "id": script.get("id", "unknown"),
                            "output": script.get("output", ""),
                            "cvss": None
                        })
                
                normalized.append({
                    "ip": host,
                    "port": port["portid"],
                    "protocol": port["protocol"],
                    "service": port.get("service", {}).get("name", "unknown"),
                    "vulnerabilities": vulns
                })
    
    return normalized