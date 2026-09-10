"""Extended tool catalog for ``ronin add`` / ``ronin search``.

A curated slice of the awesome-pentest landscape that has a clean, scriptable
install on Arch/Linux.  These do NOT have RoninSuite adapters (no parsing /
findings) - ``ronin add`` just installs the binary so it's on PATH for manual
use.  Tools that *do* have adapters live in ``ronin.tools.registry.CATALOG``.

Recipe keys, tried in order by the installer:  pacman -> aur -> go -> pipx -> git
(git clones into ``$RONIN_HOME/tools/<name>`` and is not added to PATH).
"""
from __future__ import annotations

EXTENDED: dict[str, dict] = {
    # ── recon / attack surface ────────────────────────────────────────────
    "assetfinder": {"category": "recon", "desc": "Find domains and subdomains related to a domain",
                    "install": {"go": "github.com/tomnomnom/assetfinder@latest"},
                    "url": "https://github.com/tomnomnom/assetfinder"},
    "findomain": {"category": "recon", "desc": "Fast cross-platform subdomain enumerator",
                  "install": {"aur": "findomain"}, "url": "https://github.com/Findomain/Findomain"},
    "sublist3r": {"category": "recon", "desc": "OSINT subdomain enumeration",
                  "install": {"pipx": "sublist3r"}, "url": "https://github.com/aboul3la/Sublist3r"},
    "shuffledns": {"category": "recon", "desc": "massdns wrapper for subdomain brute-force + resolve",
                   "install": {"go": "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
                   "url": "https://github.com/projectdiscovery/shuffledns"},
    "puredns": {"category": "recon", "desc": "Fast, accurate subdomain brute-force and resolver",
                "install": {"go": "github.com/d3mondev/puredns/v2@latest"},
                "url": "https://github.com/d3mondev/puredns"},
    "dnsgen": {"category": "recon", "desc": "Generate permutation wordlists for subdomains",
               "install": {"pipx": "dnsgen"}, "url": "https://github.com/ProjectAnte/dnsgen"},
    "cero": {"category": "recon", "desc": "Scrape hostnames from TLS certificates",
             "install": {"go": "github.com/glebarez/cero@latest"}, "url": "https://github.com/glebarez/cero"},
    "asnmap": {"category": "recon", "desc": "Map an organisation's netblocks via ASN",
               "install": {"go": "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
               "url": "https://github.com/projectdiscovery/asnmap"},
    "uncover": {"category": "recon", "desc": "Query Shodan/Censys/Fofa for exposed hosts",
                "install": {"go": "github.com/projectdiscovery/uncover/cmd/uncover@latest"},
                "url": "https://github.com/projectdiscovery/uncover"},
    "tlsx": {"category": "recon", "desc": "Fast TLS grabber / analyzer",
             "install": {"go": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
             "url": "https://github.com/projectdiscovery/tlsx"},
    "cdncheck": {"category": "recon", "desc": "Detect whether an IP is behind a CDN/WAF/cloud",
                 "install": {"go": "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"},
                 "url": "https://github.com/projectdiscovery/cdncheck"},

    # ── crawl / URLs ──────────────────────────────────────────────────────
    "hakrawler": {"category": "web", "desc": "Fast endpoint-discovery web crawler",
                  "install": {"go": "github.com/hakluke/hakrawler@latest"},
                  "url": "https://github.com/hakluke/hakrawler"},
    "gospider": {"category": "web", "desc": "Fast web spider written in Go",
                 "install": {"go": "github.com/jaeles-project/gospider@latest"},
                 "url": "https://github.com/jaeles-project/gospider"},
    "gau": {"category": "web", "desc": "Fetch known URLs from Wayback/CommonCrawl/AlienVault",
            "install": {"go": "github.com/lc/gau/v2/cmd/gau@latest"}, "url": "https://github.com/lc/gau"},
    "waymore": {"category": "web", "desc": "Pull URLs + responses from web archives",
                "install": {"pipx": "waymore"}, "url": "https://github.com/xnl-h4ck3r/waymore"},

    # ── params / fuzz ─────────────────────────────────────────────────────
    "arjun": {"category": "web", "desc": "HTTP parameter discovery",
              "install": {"pipx": "arjun"}, "url": "https://github.com/s0md3v/Arjun"},
    "paramspider": {"category": "web", "desc": "Mine parameters from web archives",
                    "install": {"pipx": "paramspider"}, "url": "https://github.com/devanshbatham/ParamSpider"},
    "x8": {"category": "web", "desc": "Fast hidden-parameter discovery (Rust)",
           "install": {"aur": "x8"}, "url": "https://github.com/Sh1Yo/x8"},
    "gobuster": {"category": "fuzz", "desc": "Directory / DNS / vhost brute-forcer",
                 "install": {"pacman": "gobuster"}, "url": "https://github.com/OJ/gobuster"},
    "wfuzz": {"category": "fuzz", "desc": "Web application fuzzer",
              "install": {"pipx": "wfuzz"}, "url": "https://github.com/xmendez/wfuzz"},
    "dirsearch": {"category": "fuzz", "desc": "Web path scanner",
                  "install": {"pipx": "dirsearch"}, "url": "https://github.com/maurosoria/dirsearch"},
    "gowitness": {"category": "web", "desc": "Screenshot web pages at scale",
                  "install": {"go": "github.com/sensepost/gowitness@latest"},
                  "url": "https://github.com/sensepost/gowitness"},

    # ── vuln (web) ────────────────────────────────────────────────────────
    "dalfox": {"category": "vuln", "desc": "Fast XSS scanner and analyzer",
               "install": {"go": "github.com/hahwul/dalfox/v2@latest"}, "url": "https://github.com/hahwul/dalfox"},
    "crlfuzz": {"category": "vuln", "desc": "Scan for CRLF injection",
                "install": {"go": "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"},
                "url": "https://github.com/dwisiswant0/crlfuzz"},
    "joomscan": {"category": "vuln", "desc": "Joomla vulnerability scanner",
                 "install": {"aur": "joomscan"}, "url": "https://github.com/OWASP/joomscan"},
    "droopescan": {"category": "vuln", "desc": "Drupal / SilverStripe / WordPress scanner",
                   "install": {"pipx": "droopescan"}, "url": "https://github.com/SamJoan/droopescan"},
    "cmseek": {"category": "vuln", "desc": "CMS detection and exploitation suite",
               "install": {"git": "https://github.com/Tuhinshubhra/CMSeeK"},
               "url": "https://github.com/Tuhinshubhra/CMSeeK"},

    # ── exploitation ──────────────────────────────────────────────────────
    "ssrfmap": {"category": "exploit", "desc": "Automatic SSRF fuzzer and exploiter",
                "install": {"git": "https://github.com/swisskyrepo/SSRFmap"},
                "url": "https://github.com/swisskyrepo/SSRFmap"},
    "tplmap": {"category": "exploit", "desc": "Server-side template injection exploiter",
               "install": {"git": "https://github.com/epinna/tplmap"}, "url": "https://github.com/epinna/tplmap"},
    "jwt-tool": {"category": "exploit", "desc": "Test, forge and crack JWTs",
                 "install": {"git": "https://github.com/ticarpi/jwt_tool"},
                 "url": "https://github.com/ticarpi/jwt_tool"},
    "nosqlmap": {"category": "exploit", "desc": "Automated NoSQL injection",
                 "install": {"git": "https://github.com/codingo/NoSQLMap"},
                 "url": "https://github.com/codingo/NoSQLMap"},

    # ── AD / network ──────────────────────────────────────────────────────
    "impacket": {"category": "ad", "desc": "Protocol classes + tools: secretsdump, psexec, ntlmrelayx",
                 "install": {"pacman": "impacket"}, "url": "https://github.com/fortra/impacket"},
    "certipy": {"category": "ad", "desc": "AD Certificate Services enumeration and abuse",
                "install": {"pipx": "certipy-ad"}, "url": "https://github.com/ly4k/Certipy"},
    "bloodhound-python": {"category": "ad", "desc": "BloodHound data collector (Python)",
                          "install": {"pipx": "bloodhound"}, "url": "https://github.com/dirkjanm/BloodHound.py"},
    "ldapdomaindump": {"category": "ad", "desc": "Dump AD info over LDAP to HTML/JSON",
                       "install": {"pipx": "ldapdomaindump"}, "url": "https://github.com/dirkjanm/ldapdomaindump"},
    "mitm6": {"category": "ad", "desc": "IPv6 DNS takeover to relay into AD",
              "install": {"pipx": "mitm6"}, "url": "https://github.com/dirkjanm/mitm6"},
    "responder": {"category": "ad", "desc": "LLMNR / NBT-NS / mDNS poisoner",
                  "install": {"pacman": "responder"}, "url": "https://github.com/lgandx/Responder"},
    "smbmap": {"category": "ad", "desc": "SMB share enumeration and access checks",
               "install": {"pipx": "smbmap"}, "url": "https://github.com/ShawnDEvans/smbmap"},
    "evil-winrm": {"category": "ad", "desc": "WinRM shell for pentesting",
                   "install": {"aur": "evil-winrm"}, "url": "https://github.com/Hackplayers/evil-winrm"},
    "pypykatz": {"category": "cred", "desc": "Mimikatz functionality in pure Python",
                 "install": {"pipx": "pypykatz"}, "url": "https://github.com/skelsec/pypykatz"},

    # ── cloud ─────────────────────────────────────────────────────────────
    "scoutsuite": {"category": "cloud", "desc": "Multi-cloud security auditing",
                   "install": {"pipx": "scoutsuite"}, "url": "https://github.com/nccgroup/ScoutSuite"},
    "prowler": {"category": "cloud", "desc": "AWS/Azure/GCP/K8s security assessments",
                "install": {"pipx": "prowler"}, "url": "https://github.com/prowler-cloud/prowler"},
    "cloud-enum": {"category": "cloud", "desc": "Enumerate public AWS/Azure/GCP resources",
                   "install": {"git": "https://github.com/initstring/cloud_enum"},
                   "url": "https://github.com/initstring/cloud_enum"},
    "s3scanner": {"category": "cloud", "desc": "Find open S3 buckets and dump their contents",
                  "install": {"go": "github.com/sa7mon/s3scanner@latest"},
                  "url": "https://github.com/sa7mon/S3Scanner"},

    # ── OSINT ─────────────────────────────────────────────────────────────
    "spiderfoot": {"category": "osint", "desc": "OSINT automation framework",
                   "install": {"pipx": "spiderfoot"}, "url": "https://github.com/smicallef/spiderfoot"},
    "sherlock": {"category": "osint", "desc": "Hunt a username across social networks",
                 "install": {"pipx": "sherlock-project"}, "url": "https://github.com/sherlock-project/sherlock"},
    "holehe": {"category": "osint", "desc": "Check which sites an email is registered on",
               "install": {"pipx": "holehe"}, "url": "https://github.com/megadose/holehe"},

    # ── utils / glue ──────────────────────────────────────────────────────
    "anew": {"category": "util", "desc": "Append only new lines to a file",
             "install": {"go": "github.com/tomnomnom/anew@latest"}, "url": "https://github.com/tomnomnom/anew"},
    "gf": {"category": "util", "desc": "grep wrapper with recon pattern packs",
           "install": {"go": "github.com/tomnomnom/gf@latest"}, "url": "https://github.com/tomnomnom/gf"},
    "qsreplace": {"category": "util", "desc": "Replace query-string values for fuzzing",
                  "install": {"go": "github.com/tomnomnom/qsreplace@latest"},
                  "url": "https://github.com/tomnomnom/qsreplace"},
    "unfurl": {"category": "util", "desc": "Pull apart URLs from stdin",
               "install": {"go": "github.com/tomnomnom/unfurl@latest"}, "url": "https://github.com/tomnomnom/unfurl"},
    "interactsh-client": {"category": "util", "desc": "Out-of-band interaction server client (blind SSRF/RCE)",
                          "install": {"go": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
                          "url": "https://github.com/projectdiscovery/interactsh"},
    "notify": {"category": "util", "desc": "Stream results to Slack/Discord/Telegram",
               "install": {"go": "github.com/projectdiscovery/notify/cmd/notify@latest"},
               "url": "https://github.com/projectdiscovery/notify"},
    "name-that-hash": {"category": "cred", "desc": "Identify hash types",
                       "install": {"pipx": "name-that-hash"}, "url": "https://github.com/HashPals/Name-That-Hash"},
}


def categories() -> list[str]:
    return sorted({v["category"] for v in EXTENDED.values()})
