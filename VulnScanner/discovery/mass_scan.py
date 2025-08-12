# Vuln Hunter - Masscan Integration
# DO NOT USE ILLEGALLY. Only scan networks you own or have permission to scan.
import asyncio
import json
from typing import Dict, List

async def run_masscan(target: str, ports: str = "1-65535", rate: str = "1000") -> Dict[str, List[dict]]:
    """
    Run masscan to discover open ports on target network.
    
    Args:
        target: IP range or subnet (e.g., '192.168.1.0/24')
        ports: Port range to scan (default: all ports)
        rate: Packets per second (default: 1000)
    
    Returns:
        Dictionary with discovered hosts and ports
    """
    cmd = f"masscan {target} -p{ports} --rate={rate} --output-format json"
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            raise Exception(f"Masscan error: {stderr.decode()}")
        
        results = json.loads(stdout.decode())
        return {"hosts": results}
        
    except Exception as e:
        raise Exception(f"Masscan execution failed: {str(e)}")