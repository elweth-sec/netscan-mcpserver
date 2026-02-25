from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def snmpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "161",
    community: Optional[str] = None,
    oid: Optional[str] = None,
    bruteforce: bool = False,
    community_file: Optional[str] = None,
    bruteforce_workers: int = 1,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan SNMP services and enumerate device information.

    SNMPv1/v2c uses community strings (default: "public", "private").

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               SNMP port (default: "161")
        community:          Community string to test (e.g. "public")
        oid:                OID to query ("all" to dump everything, or specific OID)
        bruteforce:         Enable community string brute-force
        community_file:     File with community strings
        bruteforce_workers: Concurrent brute-force workers (default: 1)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)

    Examples:
        snmpscan(targets="10.0.0.0/24", community="public", oid="all")
        snmpscan(targets="10.0.0.0/24", bruteforce=True, community_file="/tmp/communities.txt")
    """
    c = base_cmd("snmpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if community:
        c.extend(["-c", community])
    if oid:
        c.extend(["--oid", oid])
    if bruteforce:
        c.append("--bruteforce")
    if community_file:
        c.extend(["-C", community_file])
    if bruteforce_workers != 1:
        c.extend(["-W", str(bruteforce_workers)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def ftpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "21",
    username: Optional[str] = None,
    password: Optional[str] = None,
    bruteforce: bool = False,
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
    bruteforce_workers: int = 5,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan FTP services. Detects anonymous access automatically.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               FTP port (default: "21")
        username:           Username to test
        password:           Password to test
        bruteforce:         Enable credential brute-force
        username_file:      File with usernames
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 5)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("ftpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if bruteforce:
        c.append("--bruteforce")
    if username_file:
        c.extend(["-U", username_file])
    if password_file:
        c.extend(["-P", password_file])
    if bruteforce_workers != 5:
        c.extend(["-W", str(bruteforce_workers)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def rsyncscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "873",
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan rsync services to discover accessible modules (shares).

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        port:        rsync port (default: "873")
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("rsyncscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def rpcscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "111",
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan RPC portmapper services and enumerate registered RPC endpoints.

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        port:        RPC portmapper port (default: "111")
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("rpcscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def rtspscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "554",
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan RTSP (Real Time Streaming Protocol) services — cameras, media servers.

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        port:        RTSP port (default: "554")
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("rtspscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def jdwpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "8000",
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan for exposed Java Debug Wire Protocol (JDWP) services.

    JDWP endpoints allow arbitrary code execution on Java applications.
    Common ports: 8000, 5005, 9009.

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        port:        JDWP port (default: "8000")
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("jdwpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
