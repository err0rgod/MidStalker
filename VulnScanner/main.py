# Vuln Hunter - Main Orchestrator
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
import asyncio
from typing import List, Dict
from pathlib import Path
from discovery.masscan_scan import run_masscan
from discovery.nmap_nse import run_nmap_nse
from parsers.result_parser import normalize_results
from exploit.exploit_matcher import search_exploits
from report.report_generator import generate_json_report, generate_html_report

async def main(target: str):
    """
    Main workflow: discovery → scanning → parsing → matching → reporting.
    
    Args:
        target: Target network (e.g., '192.168.1.0/24')
    """
    print(f"[*] Starting Vuln Hunter scan for {target}")
    
    # Discovery phase
    print("[*] Running masscan for host discovery")
    masscan_results = await run_masscan(target)
    hosts = [h["ip"] for h in masscan_results.get("hosts", [])]
    
    # Scanning phase
    print("[*] Running nmap NSE scans on discovered hosts")
    nmap_results = []
    for host in hosts:
        try:
            result = await run_nmap_nse(host)
            nmap_results.append(result)
        except Exception as e:
            print(f"[-] Error scanning {host}: {str(e)}")
    
    # Parsing phase
    print("[*] Normalizing results")
    normalized = []
    for result in nmap_results:
        normalized.extend(normalize_results("nmap", result))
    
    # Exploit matching
    print("[*] Searching for matching exploits")
    cves = []
    for item in normalized:
        for vuln in item.get("vulnerabilities", []):
            if "CVE-" in vuln.get("id", ""):
                cves.append(vuln["id"])
    
    exploit_matches = await search_exploits(list(set(cves)))
    
    # Add exploit info to results
    for item in normalized:
        for vuln in item.get("vulnerabilities", []):
            if vuln["id"] in exploit_matches:
                vuln["exploits"] = exploit_matches[vuln["id"]]
    
    # Reporting phase
    print("[*] Generating reports")
    Path("reports").mkdir(exist_ok=True)
    generate_json_report(normalized, "reports/results.json")
    generate_html_report(normalized, "reports/results.html")
    
    print("[+] Scan completed. Reports saved to 'reports/' directory")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python main.py <target>")
        print("Example: python main.py 192.168.1.0/24")
        sys.exit(1)
    
    asyncio.run(main(sys.argv[1]))