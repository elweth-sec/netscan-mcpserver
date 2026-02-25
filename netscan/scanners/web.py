from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def httpscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    ports: str = "80,443",
    verb: str = "GET",
    method: str = "http,https",
    path: str = "/",
    data: Optional[str] = None,
    useragent: Optional[str] = None,
    http_auth: Optional[str] = None,
    cookies: Optional[str] = None,
    headers: Optional[str] = None,
    dir_bruteforce: Optional[str] = None,
    extensions: Optional[str] = None,
    dir_workers: int = 5,
    proxy: Optional[str] = None,
    modules: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan HTTP/HTTPS services, detect technologies, and enumerate web content.

    Args:
        targets:        Target IP, CIDR, or hostname
        target_file:    File with one target per line
        ports:          Ports to scan (default: "80,443")
        verb:           HTTP method/verb (default: "GET")
        method:         Protocols to try: "http", "https", or "http,https"
        path:           URL path to request (default: "/")
        data:           POST body data
        useragent:      Custom User-Agent string
        http_auth:      HTTP Basic Auth in "user:password" format
        cookies:        Cookies as "KEY=VALUE" pairs
        headers:        Custom headers as "KEY: VALUE" pairs
        dir_bruteforce: Path to wordlist for directory enumeration
        extensions:     File extensions to try (e.g. "php,asp,html")
        dir_workers:    Concurrent directory bruteforce workers (default: 5)
        proxy:          Proxy URL (e.g. "http://127.0.0.1:8080")
        modules:        Comma-separated netscan modules to run
        workers:        Concurrent scan workers (default: 10)
        timeout:        Connection timeout in seconds (default: 5)
        delay:          Delay between connections (default: 0)
        resume:         Resume from index (default: 0)
        nodb:           Skip Elasticsearch storage (default: True)

    Examples:
        httpscan(targets="10.0.0.0/24", ports="80,443,8080,8443")
        httpscan(targets="10.0.0.1", path="/admin", http_auth="admin:admin")
        httpscan(targets="10.0.0.1", dir_bruteforce="/usr/share/wordlists/dirb/common.txt")
    """
    c = base_cmd("httpscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", ports, "--verb", verb, "--method", method, "--path", path])
    if data:
        c.extend(["--data", data])
    if useragent:
        c.extend(["--useragent", useragent])
    if http_auth:
        c.extend(["--http-auth", http_auth])
    if cookies:
        c.extend(["--cookies", cookies])
    if headers:
        c.extend(["--headers", headers])
    if dir_bruteforce:
        c.extend(["--dir-bruteforce", dir_bruteforce])
        if extensions:
            c.extend(["-x", extensions])
        if dir_workers != 5:
            c.extend(["-W", str(dir_workers)])
    if proxy:
        c.extend(["--proxy", proxy])
    if modules:
        c.extend(["-m", modules])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def tlsscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "443",
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Scan TLS/SSL services to retrieve certificates and enumerate cipher suites.

    Args:
        targets:     Target IP, CIDR, or hostname
        target_file: File with one target per line
        port:        Port to scan (default: "443")
        workers:     Concurrent workers (default: 10)
        timeout:     Connection timeout in seconds (default: 5)
        delay:       Delay between connections (default: 0)
        resume:      Resume from index (default: 0)
        nodb:        Skip Elasticsearch storage (default: True)
    """
    c = base_cmd("tlsscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
