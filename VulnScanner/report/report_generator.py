# Vuln Hunter - Report Generator
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
import json
from typing import List, Dict
from pathlib import Path

def generate_json_report(results: List[Dict], output_file: str) -> None:
    """
    Generate JSON report from scan results.
    
    Args:
        results: List of vulnerability records
        output_file: Path to output file
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

def generate_html_report(results: List[Dict], output_file: str) -> None:
    """
    Generate basic HTML report from scan results.
    
    Args:
        results: List of vulnerability records
        output_file: Path to output file
    """
    html = """<!DOCTYPE html>
<html>
<head>
    <title>Vuln Hunter Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .vuln { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }
        .critical { background-color: #ffdddd; }
        .high { background-color: #ffeedd; }
        .medium { background-color: #ffffdd; }
        .low { background-color: #ddffdd; }
    </style>
</head>
<body>
    <h1>Vuln Hunter Report</h1>
    <div id="results">
"""

    for item in results:
        html += f"""
        <div class="vuln">
            <h3>{item['ip']}:{item['port']} ({item['protocol']}/{item['service']})</h3>
            <ul>
"""
        for vuln in item.get('vulnerabilities', []):
            html += f"<li><strong>{vuln.get('id', 'Unknown')}</strong>: {vuln.get('output', 'No details')}</li>\n"
        
        html += """
            </ul>
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    with open(output_file, 'w') as f:
        f.write(html)