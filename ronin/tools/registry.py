"""Adapter registry + the full tool catalog `ronin doctor` knows how to install.

Adapters that have a working implementation are imported and registered here.
The CATALOG dict additionally lists tools that are planned but not yet wired, so
``ronin doctor`` can still detect/install the whole offensive kit today.
"""
from __future__ import annotations

from ronin.tools.base import ToolAdapter
from ronin.tools.commix import CommixAdapter
from ronin.tools.feroxbuster import FeroxbusterAdapter
from ronin.tools.ffuf import FfufAdapter
from ronin.tools.httpx import HttpxAdapter
from ronin.tools.hydra import HydraAdapter
from ronin.tools.naabu import NaabuAdapter
from ronin.tools.nikto import NiktoAdapter
from ronin.tools.nmap import NmapAdapter
from ronin.tools.nuclei import NucleiAdapter
from ronin.tools.sqlmap import SqlmapAdapter
from ronin.tools.subfinder import SubfinderAdapter
from ronin.tools.testssl import TestsslAdapter

_ADAPTERS: dict[str, ToolAdapter] = {
    a.name: a
    for a in (
        # recon
        SubfinderAdapter(),
        # scanning
        NmapAdapter(),
        NaabuAdapter(),
        # web
        HttpxAdapter(),
        FfufAdapter(),
        FeroxbusterAdapter(),
        # vuln
        NucleiAdapter(),
        NiktoAdapter(),
        TestsslAdapter(),
        # exploitation (active)
        SqlmapAdapter(),
        HydraAdapter(),
        CommixAdapter(),
    )
}


def adapters() -> dict[str, ToolAdapter]:
    return dict(_ADAPTERS)


def get(name: str) -> ToolAdapter:
    try:
        return _ADAPTERS[name]
    except KeyError:
        raise KeyError(f"no adapter named {name!r}. have: {', '.join(sorted(_ADAPTERS))}")


# name -> {category, aggressive, install recipes, doc}.  Adapter entries above
# override the first three from the class itself; this is the provisioning map.
CATALOG: dict[str, dict] = {
    # -- recon / osint ----------------------------------------------------------
    "subfinder": {"category": "recon", "install": {"pacman": "subfinder", "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}},
    "amass": {"category": "recon", "install": {"pacman": "amass"}},
    "dnsx": {"category": "recon", "install": {"go": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}},
    "theharvester": {"category": "recon", "binary": "theHarvester", "install": {"pacman": "theharvester"}},
    "waybackurls": {"category": "recon", "install": {"go": "github.com/tomnomnom/waybackurls@latest"}},
    "gau": {"category": "recon", "install": {"go": "github.com/lc/gau/v2/cmd/gau@latest"}},
    # -- scanning ------------------------------------------------------------
    "nmap": {"category": "scan", "install": {"pacman": "nmap"}},
    "naabu": {"category": "scan", "install": {"go": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}},
    "masscan": {"category": "scan", "install": {"pacman": "masscan"}},
    "rustscan": {"category": "scan", "install": {"aur": "rustscan"}},
    # -- web ----------------------------------------------------------------
    "httpx": {"category": "web", "install": {"go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"}},
    "katana": {"category": "web", "install": {"go": "github.com/projectdiscovery/katana/cmd/katana@latest"}},
    "ffuf": {"category": "web", "install": {"pacman": "ffuf", "go": "github.com/ffuf/ffuf/v2@latest"}},
    "feroxbuster": {"category": "web", "install": {"pacman": "feroxbuster"}},
    "whatweb": {"category": "web", "install": {"pacman": "whatweb"}},
    "wafw00f": {"category": "web", "install": {"pacman": "wafw00f"}},
    # -- vuln -------------------------------------------------------------------
    "nuclei": {"category": "vuln", "install": {"pacman": "nuclei", "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}},
    "nikto": {"category": "vuln", "install": {"pacman": "nikto"}},
    "testssl": {"category": "vuln", "binary": "testssl.sh", "install": {"pacman": "testssl.sh"}},
    "sslscan": {"category": "vuln", "install": {"pacman": "sslscan"}},
    "wpscan": {"category": "vuln", "install": {"aur": "wpscan"}, "aggressive": True},
    # -- exploitation ------------------------------------------------------
    "sqlmap": {"category": "exploit", "install": {"pacman": "sqlmap"}, "aggressive": True},
    "hydra": {"category": "exploit", "install": {"pacman": "hydra"}, "aggressive": True},
    "medusa": {"category": "exploit", "install": {"pacman": "medusa"}, "aggressive": True},
    "commix": {"category": "exploit", "install": {"aur": "commix"}, "aggressive": True},
    # -- ad / network ------------------------------------------------------------
    "netexec": {"category": "ad", "binary": "nxc", "install": {"aur": "netexec"}, "aggressive": True},
    "enum4linux-ng": {"category": "ad", "install": {"aur": "enum4linux-ng"}},
    "kerbrute": {"category": "ad", "install": {"go": "github.com/ropnop/kerbrute@latest"}, "aggressive": True},
    # -- cracking -------------------------------------------------------------
    "hashcat": {"category": "cracking", "install": {"pacman": "hashcat"}},
    "john": {"category": "cracking", "install": {"pacman": "john"}},
}
