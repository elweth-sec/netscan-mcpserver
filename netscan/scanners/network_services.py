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
    list_files: bool = False,
    passive: bool = False,
    recurse: int = 3,
    bruteforce: bool = False,
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
    bruteforce_workers: int = 1,
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
        list_files:         List contents of the FTP directory after auth (--list)
        passive:            Use FTP passive mode (--passive)
        recurse:            Recursion depth for directory listing (default: 3)
        bruteforce:         Enable credential brute-force
        username_file:      File with usernames
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 1)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)

    Examples:
        ftpscan(targets="10.0.0.0/24")
        ftpscan(targets="192.168.1.1", username="anonymous", password="anonymous", list_files=True, recurse=5)
    """
    c = base_cmd("ftpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if passive:
        c.append("--passive")
    if list_files:
        c.append("--list")
    if recurse != 3:
        c.extend(["--recurse", str(recurse)])
    if bruteforce:
        c.append("--bruteforce")
    if username_file:
        c.extend(["-U", username_file])
    if password_file:
        c.extend(["-P", password_file])
    if bruteforce_workers != 1:
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
    rpc: bool = False,
    mounts: bool = False,
    list_files: bool = False,
    uid: int = 0,
    gid: int = 0,
    recurse: int = 1,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan RPC/NFS services and enumerate endpoints and NFS shares.

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        rpc:         List RPC entries (--rpc)
        mounts:      List NFS mount points (--mounts)
        list_files:  List contents of NFS directories (--list)
        uid:         UID to use for NFS connection (default: 0)
        gid:         GID to use for NFS connection (default: 0)
        recurse:     Recursion depth for NFS directory listing (default: 1)
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)

    Examples:
        rpcscan(targets="10.0.0.0/24", rpc=True)
        rpcscan(targets="192.168.1.1", mounts=True, list_files=True, recurse=3)
    """
    c = base_cmd("rpcscan")
    add_targets(c, targets, target_file)
    if rpc:
        c.append("--rpc")
    if mounts:
        c.append("--mounts")
    if list_files:
        c.append("--list")
    if uid != 0:
        c.extend(["--uid", str(uid)])
    if gid != 0:
        c.extend(["--gid", str(gid)])
    if recurse != 1:
        c.extend(["--recurse", str(recurse)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def rtspscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "554",
    screenshot: bool = False,
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
        screenshot:  Capture a screenshot of the RTSP stream (--screenshot)
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)

    Examples:
        rtspscan(targets="10.0.0.0/24")
        rtspscan(targets="192.168.1.1", screenshot=True)
    """
    c = base_cmd("rtspscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if screenshot:
        c.append("--screenshot")
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def jdwpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "8000",
    break_on: Optional[str] = None,
    classes: bool = False,
    system_info: bool = False,
    exec_cmd: Optional[str] = None,
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
        break_on:    Java method to break on (default: "java.net.ServerSocket.accept")
        classes:     Retrieve class information (--classes)
        system_info: Get system info, requires breakpoint so may hang (--system-info)
        exec_cmd:    Command to execute on target (--exec)
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)

    Examples:
        jdwpscan(targets="10.0.0.0/24", port="8000")
        jdwpscan(targets="192.168.1.1", classes=True, system_info=True)
        jdwpscan(targets="192.168.1.1", exec_cmd="id")
    """
    c = base_cmd("jdwpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if break_on:
        c.extend(["--break-on", break_on])
    if classes:
        c.append("--classes")
    if system_info:
        c.append("--system-info")
    if exec_cmd:
        c.extend(["--exec", exec_cmd])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
