from typing import Optional

from netscan import mcp
from netscan.core import add_common, add_targets, base_cmd, run


@mcp.tool()
async def smbscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    port: str = "445",
    null_session: bool = False,
    guest: bool = False,
    username: Optional[str] = None,
    domain: str = "WORKGROUP",
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    kerberos_ticket: Optional[str] = None,
    dc_ip: Optional[str] = None,
    shares: bool = False,
    list_shares: bool = False,
    recurse: Optional[int] = None,
    search: Optional[str] = None,
    get_file: Optional[str] = None,
    exec_method: Optional[str] = None,
    cmd: Optional[str] = None,
    powershell: Optional[str] = None,
    dump_sam: bool = False,
    dump_lsa: bool = False,
    users: bool = False,
    groups: bool = False,
    admins: bool = False,
    processes: bool = False,
    sessions: bool = False,
    loggedin: bool = False,
    passpol: bool = False,
    rid_brute: Optional[str] = None,
    modules: Optional[str] = None,
    bruteforce: bool = False,
    simple_bruteforce: bool = False,
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
    ntlm_file: Optional[str] = None,
    bruteforce_workers: int = 5,
    bruteforce_delay: float = 0,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Comprehensive SMB scanning, enumeration, and exploitation.

    Authentication methods:
        null_session=True        Anonymous access
        guest=True               Guest account
        username + password      Standard credentials
        ntlm_hash                Pass-the-hash (LM:NTLM or NTLM format)
        kerberos_ticket + dc_ip  Kerberos ticket authentication

    Enumeration flags (combine freely):
        shares=True              List available shares
        list_shares=True         List share contents
        users/groups/admins      Enumerate users, groups, local admins
        sessions/loggedin        Active sessions and logged-in users
        processes=True           Running processes
        passpol=True             Password policy
        rid_brute="500-1100"     RID brute-force for user enumeration

    Secrets:
        dump_sam=True            Dump SAM database hashes
        dump_lsa=True            Dump LSA secrets
        search="password"        Search file content for secrets

    Remote execution (exec_method: wmiexec/mmcexec/smbexec/atexec):
        cmd="whoami"             Execute system command
        powershell="Get-Process" Execute PowerShell command

    Brute-force:
        bruteforce=True          Test username_file × password_file
        simple_bruteforce=True   Try username=password for each user
        ntlm_file                File with NTLM hashes for pass-the-hash spray
    """
    c = base_cmd("smbscan")
    add_targets(c, targets, target_file)
    c.extend(["-p", port, "-d", domain])
    if null_session:
        c.append("--null")
    if guest:
        c.append("--guest")
    if username:
        c.extend(["-u", username])
    if password:
        c.extend(["--pass", password])
    if ntlm_hash:
        c.extend(["--hash", ntlm_hash])
    if kerberos_ticket:
        c.extend(["-k", kerberos_ticket])
    if dc_ip:
        c.extend(["--dc-ip", dc_ip])
    if shares:
        c.append("--shares")
    if list_shares:
        c.append("--list")
    if recurse is not None:
        c.extend(["--recurse", str(recurse)])
    if search:
        c.extend(["--search", search])
    if get_file:
        c.extend(["--get-file", get_file])
    if exec_method:
        c.extend(["--exec-method", exec_method])
    if cmd:
        c.extend(["--cmd", cmd])
    if powershell:
        c.extend(["--powershell", powershell])
    if dump_sam:
        c.append("--sam")
    if dump_lsa:
        c.append("--lsa")
    if users:
        c.append("--users")
    if groups:
        c.append("--groups")
    if admins:
        c.append("--admins")
    if processes:
        c.append("--processes")
    if sessions:
        c.append("--sessions")
    if loggedin:
        c.append("--loggedin")
    if passpol:
        c.append("--passpol")
    if rid_brute:
        c.extend(["--rid-brute", rid_brute])
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
    if ntlm_file:
        c.extend(["--ntlm-file", ntlm_file])
    if bruteforce_workers != 5:
        c.extend(["-W", str(bruteforce_workers)])
    if bruteforce_delay > 0:
        c.extend(["--bruteforce-delay", str(bruteforce_delay)])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)


@mcp.tool()
async def adscan(
    targets: Optional[str] = None,
    target_file: Optional[str] = None,
    null_session: bool = False,
    guest: bool = False,
    username: Optional[str] = None,
    domain: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    kerberos_ticket: Optional[str] = None,
    dc_ip: Optional[str] = None,
    aes_key: Optional[str] = None,
    # Enumeration
    domains: bool = False,
    users: bool = False,
    admins: bool = False,
    rdp_users: bool = False,
    groups: bool = False,
    hosts: bool = False,
    dns: bool = False,
    passpol: bool = False,
    trusts: bool = False,
    gpos: bool = False,
    search: Optional[str] = None,
    list_groups: Optional[str] = None,
    list_users: Optional[str] = None,
    constrained_delegation: bool = False,
    rbcd: bool = False,
    # Attacks
    kerberoasting: bool = False,
    asreproasting: bool = False,
    gpp: bool = False,
    # ADCS
    adcs: bool = False,
    cas: bool = False,
    cert_templates: bool = False,
    # Domain admin
    laps: bool = False,
    gmsa: bool = False,
    ntds: Optional[str] = None,
    vuln_gpos: bool = False,
    # Connection
    no_ssl: bool = False,
    ldap_protocol: Optional[str] = None,
    workers: int = 10,
    timeout: int = 5,
    delay: float = 0,
    resume: int = 0,
    nodb: bool = True,
) -> str:
    """
    Active Directory enumeration, attacks, and certificate services (ADCS).

    Authentication:
        null_session / guest          Anonymous / guest bind
        username + domain + password  Standard AD credentials
        ntlm_hash                     Pass-the-hash
        kerberos_ticket + dc_ip       Kerberos TGT ticket
        aes_key                       AES key for Kerberos

    Enumeration (combine multiple flags):
        users / admins / groups / hosts / domains / dns
        passpol              Password policy
        trusts               Domain trusts
        gpos                 Group Policy Objects
        rdp_users            Users with RDP rights
        constrained_delegation / rbcd  Delegation misconfigs
        search="password"    Search LDAP attributes for secrets
        list_groups="user"   Groups a specific user belongs to
        list_users="group"   Members of a specific group

    Attacks:
        kerberoasting=True   Request TGS tickets for offline cracking
        asreproasting=True   Dump AS-REP for accounts without pre-auth
        gpp=True             Find passwords in Group Policy Preferences

    ADCS (Certificate Services):
        adcs=True            Discover Certificate Authorities
        cas=True             List CAs
        cert_templates=True  List certificate templates (ESC1-8 detection)

    Domain admin:
        laps=True            Dump LAPS passwords (local admin)
        gmsa=True            Dump gMSA passwords
        ntds="vss|drsuapi"   Dump NTDS.dit domain password database

    Connection:
        no_ssl=True          Use LDAP instead of LDAPS
        ldap_protocol        Override protocol: ldaps / ldap / gc
    """
    c = base_cmd("adscan")
    add_targets(c, targets, target_file)
    if null_session:
        c.append("--null")
    if guest:
        c.append("--guest")
    if username:
        c.extend(["-u", username])
    if domain:
        c.extend(["-d", domain])
    if password:
        c.extend(["--pass", password])
    if ntlm_hash:
        c.extend(["--hash", ntlm_hash])
    if kerberos_ticket:
        c.extend(["-k", kerberos_ticket])
    if dc_ip:
        c.extend(["--dc-ip", dc_ip])
    if aes_key:
        c.extend(["--aes-key", aes_key])
    if domains:
        c.append("--domains")
    if users:
        c.append("--users")
    if admins:
        c.append("--admins")
    if rdp_users:
        c.append("--rdp")
    if groups:
        c.append("--groups")
    if hosts:
        c.append("--hosts")
    if dns:
        c.append("--dns")
    if passpol:
        c.append("--passpol")
    if trusts:
        c.append("--trusts")
    if gpos:
        c.append("--gpos")
    if search:
        c.extend(["--search", search])
    if list_groups:
        c.extend(["--list-groups", list_groups])
    if list_users:
        c.extend(["--list-users", list_users])
    if constrained_delegation:
        c.append("--constrained-delegation")
    if rbcd:
        c.append("--rbcd")
    if kerberoasting:
        c.append("--kerberoasting")
    if asreproasting:
        c.append("--asreproasting")
    if gpp:
        c.append("--gpp")
    if adcs:
        c.append("--adcs")
    if cas:
        c.append("--cas")
    if cert_templates:
        c.append("--cert-templates")
    if laps:
        c.append("--laps")
    if gmsa:
        c.append("--gmsa")
    if ntds:
        c.extend(["--ntds", ntds])
    if vuln_gpos:
        c.append("--vuln-gpos")
    if no_ssl:
        c.append("--no-ssl")
    if ldap_protocol:
        c.extend(["--ldap-protocol", ldap_protocol])
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
