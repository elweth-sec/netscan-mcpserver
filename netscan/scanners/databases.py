from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def mysqlscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "3306",
    username: Optional[str] = None,
    password: Optional[str] = None,
    list_dbs: bool = False,
    dump_hashes: bool = False,
    sql_query: Optional[str] = None,
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
    Scan MySQL database services.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               MySQL port (default: "3306")
        username:           Username to authenticate with
        password:           Password to authenticate with
        list_dbs:           List available databases
        dump_hashes:        Dump user password hashes
        sql_query:          Execute a custom SQL query (e.g. "SELECT version()")
        bruteforce:         Enable credential brute-force
        username_file:      File with usernames (username or username:password format)
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 5)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("mysqlscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if list_dbs:
        c.append("--dbs")
    if dump_hashes:
        c.append("--hashes")
    if sql_query:
        c.extend(["--sql", sql_query])
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
async def mssqlscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "1433",
    domain: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    list_dbs: bool = False,
    list_links: bool = False,
    list_admins: bool = False,
    dump_hashes: bool = False,
    sql_query: Optional[str] = None,
    cmd: Optional[str] = None,
    link: Optional[str] = None,
    admin_check: bool = False,
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
    Scan Microsoft SQL Server (MSSQL) services.

    Supports SQL Authentication and Windows Authentication (NTLM/Kerberos).

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               MSSQL port (default: "1433")
        domain:             Windows domain for authentication
        username:           Username to authenticate with
        password:           Password to authenticate with
        ntlm_hash:          NTLM hash for pass-the-hash
        list_dbs:           List databases
        list_links:         List linked servers
        list_admins:        List database administrators
        dump_hashes:        Dump user hashes
        sql_query:          Execute SQL query (e.g. "SELECT @@version")
        cmd:                Execute OS command via xp_cmdshell
        link:               Execute query on a linked server
        admin_check:        Verify if current user has admin privileges
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
    c = base_cmd("mssqlscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if domain:
        c.extend(["-d", domain])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if ntlm_hash:
        c.extend(["--hash", ntlm_hash])
    if list_dbs:
        c.append("--dbs")
    if list_links:
        c.append("--links")
    if list_admins:
        c.append("--admins")
    if dump_hashes:
        c.append("--hashes")
    if sql_query:
        c.extend(["--sql", sql_query])
    if cmd:
        c.extend(["--cmd", cmd])
    if link:
        c.extend(["--link", link])
    if admin_check:
        c.append("--admin-check")
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
async def postgrescan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "5432",
    username: Optional[str] = None,
    password: Optional[str] = None,
    list_dbs: bool = False,
    sql_query: Optional[str] = None,
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
    Scan PostgreSQL database services.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               PostgreSQL port (default: "5432")
        username:           Username to authenticate with
        password:           Password to authenticate with
        list_dbs:           List available databases
        sql_query:          Execute SQL query (e.g. "SELECT version()")
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
    c = base_cmd("postgrescan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if list_dbs:
        c.append("--dbs")
    if sql_query:
        c.extend(["--sql", sql_query])
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
async def mongoscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "27017",
    username: Optional[str] = None,
    password: Optional[str] = None,
    list_dbs: bool = False,
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
    Scan MongoDB services. Detects unauthenticated access automatically.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               MongoDB port (default: "27017")
        username:           Username to authenticate with
        password:           Password to authenticate with
        list_dbs:           List available databases
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
    c = base_cmd("mongoscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if list_dbs:
        c.append("--dbs")
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
async def redisscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "6379",
    password: Optional[str] = None,
    bruteforce: bool = False,
    password_file: Optional[str] = None,
    bruteforce_workers: int = 5,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan Redis services. Detects unauthenticated access automatically.

    Args:
        targets:            Target IP, CIDR, or hostname
        target_file:        File with one target per line
        port:               Redis port (default: "6379")
        password:           Password / AUTH string to test
        bruteforce:         Enable password brute-force
        password_file:      File with passwords
        bruteforce_workers: Concurrent brute-force workers (default: 5)
        workers:            Concurrent scan workers (default: 10)
        timeout:            Connection timeout in seconds (default: 5)
        delay:              Delay between connections (default: 0)
        resume:             Resume from index (default: 0)
        nodb:               Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("redisscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    if password:
        c.extend(["--pass", password])
    if bruteforce:
        c.append("--bruteforce")
    if password_file:
        c.extend(["-P", password_file])
    if bruteforce_workers != 5:
        c.extend(["-W", str(bruteforce_workers)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
