from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def pingscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Discover live hosts on a network using ICMP ping.

    Args:
        targets:     Target IP, CIDR range, or hostname (e.g. "192.168.1.0/24")
        target_file: Path to a file containing one target per line
        workers:     Number of concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections in seconds (default: 0)
        resume:      Resume scan from this index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)

    Examples:
        pingscan(targets="192.168.1.0/24", workers=300)
        pingscan(target_file="/tmp/hosts.txt", workers=100)
    """
    c = base_cmd("pingscan")
    add_targets(c, targets, target_file)
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def portscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    all_ports: bool = False,
    service_detection: bool = False,
    script: Optional[str] = None,
    script_args: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0.01,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan for open TCP ports on target hosts.

    Args:
        targets:           Target IP, CIDR, or hostname
        target_file:       File with one target per line
        ports:             Ports to scan (e.g. "80,443,8080" or "1-1024")
        top_ports:         Scan the top N most common ports (e.g. 100)
        all_ports:         Scan all 65535 ports
        service_detection: Enable nmap service/version detection (-sV)
        script:            Nmap script or category (requires service_detection=True)
        script_args:       Arguments for nmap scripts
        workers:           Concurrent workers (default: 10)
        timeout:           Connection timeout in seconds (default: 5)
        delay:             Delay between connections (default: 0.01)
        resume:            Resume from index (default: 0)
        nodb:              Skip Elasticsearch storage (default: True)

    Examples:
        portscan(targets="10.0.0.0/24", ports="22,80,443,8080", workers=300)
        portscan(target_file="/tmp/ips.txt", top_ports=100)
        portscan(targets="10.0.0.1", all_ports=True, service_detection=True)
    """
    c = base_cmd("portscan")
    add_targets(c, targets, target_file)
    if ports:
        c.extend(["-p", ports])
    elif top_ports:
        c.extend(["--top-ports", str(top_ports)])
    elif all_ports:
        c.append("-p-")
    if service_detection:
        c.append("-sV")
    if script:
        c.extend(["--script", script])
    if script_args:
        c.extend(["--script-args", script_args])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
