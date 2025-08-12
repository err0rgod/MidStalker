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

async def scan_host(host: str, semaphore: asyncio.Semaphore):
    """Scan a single host with rate limiting."""
    async with semaphore:
        try:
            print(f"  [-] Scanning {host}")
            return await run_nmap_nse(host, timeout=300)
        except Exception as e:
            print(f"  [!] Error scanning {host}: {str(e)}")
            return None

async def main(target: str):
    """
    Main workflow: discovery → scanning → parsing → matching → reporting.
    
    Args:
        target: Target network (e.g., '192.168.1.0/24')
    """
    print(f"[*] Starting Vuln Hunter scan for {target}")
    
    try:
        # Discovery phase with timeout
        print("[*] Running masscan for host discovery")
        masscan_results = await asyncio.wait_for(
            run_masscan(target, timeout=300),
            timeout=330
        )
        hosts = list({h["ip"] for h in masscan_results.get("hosts", [])})
        
        if not hosts:
            print("[!] No hosts discovered")
            return

        # Scanning phase with concurrency control
        print(f"[*] Running nmap NSE scans on {len(hosts)} discovered hosts")
        semaphore = asyncio.Semaphore(5)  # Limit concurrent scans
        scan_tasks = [scan_host(host, semaphore) for host in hosts]
        nmap_results = await asyncio.gather(*scan_tasks)
        nmap_results = [r for r in nmap_results if r is not None]
        
        if not nmap_results:
            print("[!] No valid scan results obtained")
            return

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
        
        if cves:
            exploit_matches = await search_exploits(list(set(cves)))
            # Add exploit info to results
            for item in normalized:
                for vuln in item.get("vulnerabilities", []):
                    if vuln["id"] in exploit_matches:
                        vuln["exploits"] = exploit_matches[vuln["id"]]
        else:
            print("[*] No CVEs found for exploit matching")

        # Reporting phase
        print("[*] Generating reports")
        Path("reports").mkdir(exist_ok=True)
        generate_json_report(normalized, "reports/results.json")
        generate_html_report(normalized, "reports/results.html")
        
        print("[+] Scan completed. Reports saved to 'reports/' directory")

    except asyncio.TimeoutError:
        print("[!] Scan timed out. Please try with a smaller network range or longer timeout")
    except Exception as e:
        print(f"[!] Critical error: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python main.py <target>")
        print("Example: python main.py 192.168.1.0/24")
        sys.exit(1)
    
    try:
        asyncio.run(main(sys.argv[1]))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")