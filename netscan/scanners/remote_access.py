from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def sshscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "22",
    username: Optional[str] = None,
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    cmd: Optional[str] = None,
    modules: Optional[str] = None,
    bruteforce: bool = False,
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
    bruteforce_workers: int = 1,
    bruteforce_delay: float = 0,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan SSH services, test credentials, and execute remote commands.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               SSH port (default: "22")
        username:           Username to authenticate with
        password:           Password to authenticate with
        key_file:           Path to SSH private key file
        cmd:                Command to execute on authenticated hosts
        modules:            Comma-separated netscan modules to run
        bruteforce:         Enable credential brute-force mode
        username_file:      File with usernames for brute-force
        password_file:      File with passwords for brute-force
        bruteforce_workers: Concurrent brute-force workers (default: 1)
        bruteforce_delay:   Delay between brute-force attempts in seconds
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)

    Examples:
        sshscan(targets="10.0.0.0/24", workers=100)
        sshscan(targets="10.0.0.1", username="root", password="toor", cmd="id")
        sshscan(targets="10.0.0.0/24", bruteforce=True, username_file="/tmp/users.txt", password_file="/tmp/pass.txt")
    """
    c = base_cmd("sshscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if key_file:
        c.extend(["--key", key_file])
    if cmd:
        c.extend(["--cmd", cmd])
    if modules:
        c.extend(["-m", modules])
    if bruteforce:
        c.append("--bruteforce")
    if username_file:
        c.extend(["-U", username_file])
    if password_file:
        c.extend(["-P", password_file])
    if bruteforce_workers != 1:
        c.extend(["-W", str(bruteforce_workers)])
    if bruteforce_delay > 0:
        c.extend(["--bruteforce-delay", str(bruteforce_delay)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def rdpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "3389",
    domain: str = "WORKGROUP",
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    modules: Optional[str] = None,
    bruteforce: bool = False,
    simple_bruteforce: bool = False,
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
    Scan RDP (Remote Desktop Protocol) services and test credentials.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               RDP port (default: "3389")
        domain:             Windows domain (default: "WORKGROUP")
        username:           Username to test
        password:           Password to test
        ntlm_hash:          NTLM hash for pass-the-hash authentication
        modules:            Netscan modules to run
        bruteforce:         Enable credential brute-force
        simple_bruteforce:  Try username=password combinations
        username_file:      File with usernames
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 5)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("rdpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port, "-d", domain])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if ntlm_hash:
        c.extend(["--hash", ntlm_hash])
    if modules:
        c.extend(["-m", modules])
    if bruteforce:
        c.append("--bruteforce")
    if simple_bruteforce:
        c.append("--simple-bruteforce")
    if username_file:
        c.extend(["-U", username_file])
    if password_file:
        c.extend(["-P", password_file])
    if bruteforce_workers != 5:
        c.extend(["-W", str(bruteforce_workers)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def vncscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "5900",
    password: Optional[str] = None,
    screenshot: bool = False,
    ducky: Optional[str] = None,
    bruteforce: bool = False,
    password_file: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan VNC (Virtual Network Computing) services and test credentials.

    Args:
        targets:      Target IP, CIDR, or hostname
        target_file:  File with one target per line
        port:         VNC port (default: "5900")
        password:     Password to test
        screenshot:   Capture a screenshot of the VNC session (--screenshot)
        ducky:        Path to a ducky script to execute (--ducky)
        bruteforce:   Enable password brute-force
        password_file: File with passwords for brute-force
        workers:      Concurrent scan workers (default: 10)
        timeout:      Connection timeout in seconds (default: 5)
        delay:        Delay between connections (default: 0)
        resume:       Resume from index (default: 0)
        nodb:         Skip Elasticsearch storage (default: True)

    Examples:
        vncscan(targets="10.0.0.0/24")
        vncscan(targets="192.168.1.1", password="secret", screenshot=True)
    """
    c = base_cmd("vncscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if password:
        c.extend(["--pass", password])
    if screenshot:
        c.append("--screenshot")
    if ducky:
        c.extend(["--ducky", ducky])
    if bruteforce:
        c.append("--bruteforce")
    if password_file:
        c.extend(["-P", password_file])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def telnetscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "23",
    username: Optional[str] = None,
    password: Optional[str] = None,
    cmd: Optional[str] = None,
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
    Scan Telnet services and test credentials.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               Telnet port (default: "23")
        username:           Username to test
        password:           Password to test
        cmd:                Command to execute on authenticated hosts
        bruteforce:         Enable credential brute-force
        username_file:      File with usernames
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 5)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)

    Examples:
        telnetscan(targets="10.0.0.0/24")
        telnetscan(targets="192.168.1.1", username="admin", password="admin", cmd="id")
    """
    c = base_cmd("telnetscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if cmd:
        c.extend(["--cmd", cmd])
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
async def winrmscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    domain: str = "WORKGROUP",
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    cmd: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan WinRM (Windows Remote Management) services and execute commands.

    WinRM ports: 5985 (HTTP) / 5986 (HTTPS).

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        domain:      Windows domain (default: "WORKGROUP")
        username:    Username to authenticate with
        password:    Password to authenticate with
        ntlm_hash:   NTLM hash for pass-the-hash authentication
        cmd:         Command to execute on authenticated hosts
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("winrmscan")
    add_targets(c, targets, target_file)
    c.extend(["-d", domain])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if ntlm_hash:
        c.extend(["--hash", ntlm_hash])
    if cmd:
        c.extend(["--cmd", cmd])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
