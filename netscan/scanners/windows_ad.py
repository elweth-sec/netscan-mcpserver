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
    dump_sam: Optional[str] = None,
    dump_lsa: Optional[str] = None,
    users: bool = False,
    groups: bool = False,
    admins: bool = False,
    apps: bool = False,
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
        dump_sam="regdump"       Dump SAM hashes (regdump or secdump)
        dump_lsa="regdump"       Dump LSA secrets (regdump or secdump)
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
        c.extend(["--sam", dump_sam])
    if dump_lsa:
        c.extend(["--lsa", dump_lsa])
    if users:
        c.append("--users")
    if groups:
        c.append("--groups")
    if admins:
        c.append("--admins")
    if apps:
        c.append("--apps")
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
    # Authentication
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
    target_domain: Optional[str] = None,
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
    acl: Optional[str] = None,
    users_brute: Optional[str] = None,
    # Attacks
    kerberoasting: bool = False,
    asreproasting: bool = False,
    gpp: bool = False,
    gettgt: bool = False,
    gettgs: Optional[str] = None,
    gettgs_impersonate: Optional[str] = None,
    # ADCS
    adcs: bool = False,
    cas: bool = False,
    certipy: bool = False,
    cert_templates: bool = False,
    # Domain admin
    laps: bool = False,
    gmsa: bool = False,
    smsa: bool = False,
    ntds: Optional[str] = None,
    vuln_gpos: bool = False,
    # AD modifications
    add_to_group: Optional[str] = None,
    add_to_group_user: Optional[str] = None,
    del_from_group: Optional[str] = None,
    del_from_group_user: Optional[str] = None,
    set_owner_principal: Optional[str] = None,
    set_owner_target: Optional[str] = None,
    add_computer_name: Optional[str] = None,
    add_computer_password: Optional[str] = None,
    del_object: Optional[str] = None,
    set_password_dn: Optional[str] = None,
    set_password_value: Optional[str] = None,
    # Connection
    no_ssl: bool = False,
    ldap_protocol: Optional[str] = None,
    python_ldap: bool = False,
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
        target_domain        Target domain FQDN for cross-domain enum
        users / admins / groups / hosts / domains / dns
        passpol              Password policy
        trusts               Domain trusts
        gpos                 Group Policy Objects
        rdp_users            Users with RDP rights
        constrained_delegation / rbcd  Delegation misconfigs
        search="password"    Search LDAP attributes for secrets
        list_groups="user"   Groups a specific user belongs to
        list_users="group"   Members of a specific group
        acl="object"         List interesting ACLs of a specific object (DN, name or SID)
        users_brute="file"   Check user existence via TGT request (prints KRB5ASREP if pre-auth disabled)

    Attacks:
        kerberoasting=True   Request TGS tickets for offline cracking
        asreproasting=True   Dump AS-REP for accounts without pre-auth
        gpp=True             Find passwords in Group Policy Preferences
        gettgt=True          Get a TGT for the current user
        gettgs="SPN"         Get a TGS for the specified SPN (set gettgs_impersonate for S4U2Proxy)

    ADCS (Certificate Services):
        adcs=True            Discover Certificate Authorities
        cas=True             List CAs
        certipy=True         Execute certipy
        cert_templates=True  List certificate templates (ESC1-8 detection)

    Domain admin:
        laps=True            Dump LAPS passwords (local admin)
        gmsa=True            Dump gMSA passwords
        smsa=True            Dump sMSA passwords
        ntds="vss|drsuapi"   Dump NTDS.dit domain password database

    AD Modifications:
        add_to_group + add_to_group_user           Add user to a group (both are LDAP DNs)
        del_from_group + del_from_group_user        Remove user from a group
        set_owner_principal + set_owner_target      Change object owner
        add_computer_name + add_computer_password   Add computer to domain
        del_object="ObjectDN"                       Delete LDAP entry
        set_password_dn + set_password_value        Change object password

    Connection:
        no_ssl=True          Use LDAP instead of LDAPS
        ldap_protocol        Override protocol: ldaps / ldap / gc
        python_ldap=True     Use python-ldap3 instead of impacket
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
    if target_domain:
        c.extend(["--target-domain", target_domain])
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
    if acl:
        c.extend(["--acl", acl])
    if users_brute:
        c.extend(["--users-brute", users_brute])
    if kerberoasting:
        c.append("--kerberoasting")
    if asreproasting:
        c.append("--asreproasting")
    if gpp:
        c.append("--gpp")
    if gettgt:
        c.append("--gettgt")
    if gettgs:
        args_gettgs = ["--gettgs", gettgs]
        if gettgs_impersonate:
            args_gettgs.append(gettgs_impersonate)
        c.extend(args_gettgs)
    if adcs:
        c.append("--adcs")
    if cas:
        c.append("--cas")
    if certipy:
        c.append("--certipy")
    if cert_templates:
        c.append("--cert-templates")
    if laps:
        c.append("--laps")
    if gmsa:
        c.append("--gmsa")
    if smsa:
        c.append("--smsa")
    if ntds:
        c.extend(["--ntds", ntds])
    if vuln_gpos:
        c.append("--vuln-gpos")
    if add_to_group and add_to_group_user:
        c.extend(["--add-to-group", add_to_group, add_to_group_user])
    if del_from_group and del_from_group_user:
        c.extend(["--del-from-group", del_from_group, del_from_group_user])
    if set_owner_principal and set_owner_target:
        c.extend(["--set-owner", set_owner_principal, set_owner_target])
    if add_computer_name and add_computer_password:
        c.extend(["--add-computer", add_computer_name, add_computer_password])
    if del_object:
        c.extend(["--del-object", del_object])
    if set_password_dn and set_password_value:
        c.extend(["--set-password", set_password_dn, set_password_value])
    if no_ssl:
        c.append("--no-ssl")
    if ldap_protocol:
        c.extend(["--ldap-protocol", ldap_protocol])
    if python_ldap:
        c.append("--python-ldap")
    add_common(c, workers, timeout, delay, resume, nodb)
    return await run(c)
