from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def dnsscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    dns_server: Optional[str] = None,
    tcp: bool = False,
    bruteforce_wordlist: Optional[str] = None,
    axfr: bool = False,
    dc_lookup: bool = False,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    DNS enumeration and reconnaissance.

    Args:
        targets:              Domain(s) or DNS server IPs to query
        target_file:          File with one target per line
        dns_server:           Use a specific DNS server (e.g. "8.8.8.8")
        tcp:                  Use TCP instead of UDP for queries
        bruteforce_wordlist:  Path to subdomain wordlist for brute-force
        axfr:                 Attempt DNS zone transfer (AXFR)
        dc_lookup:            Identify Domain Controllers via DNS
        workers:              Concurrent workers (default: 10)
        timeout:              Connection timeout in seconds (default: 5)
        delay:                Delay between queries (default: 0)
        resume:               Resume from index (default: 0)
        nodb:                 Skip Elasticsearch storage (default: True)

    Examples:
        dnsscan(targets="example.com", axfr=True)
        dnsscan(targets="192.168.1.0/24", dc_lookup=True)
        dnsscan(targets="example.com", bruteforce_wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    """
    c = base_cmd("dnsscan")
    add_targets(c, targets, target_file)
    if dns_server:
        c.extend(["--dns", dns_server])
    if tcp:
        c.append("--tcp")
    if bruteforce_wordlist:
        c.extend(["--bruteforce", bruteforce_wordlist])
    if axfr:
        c.append("--axfr")
    if dc_lookup:
        c.append("--dc")
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
