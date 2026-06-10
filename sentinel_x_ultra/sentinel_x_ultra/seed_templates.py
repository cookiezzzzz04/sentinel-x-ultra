"""
Seed Templates - Txt-file scaffolds for empty project folders.

When a new project is created against an empty folder, these template txt files
are copied into it so the agents have the standard recon file layout to work
against. Based on the live bug-bounty hunting workflow from:

    https://amrelsagaei.com/live-bug-bounty-hunting

The ten files match the recon pipeline:
    target.txt         -> primary target domain
    AllSubs.txt        -> aggregated subdomain list (raw)
    AliveSubs.txt      -> live, responsive subdomains only
    urls.txt           -> all archived URLs
    param.txt          -> URLs that contain query parameters
    js.txt             -> JavaScript files discovered
    xss.txt            -> candidate XSS URLs
    lfi.txt            -> candidate LFI URLs
    XSSvulnerable.txt  -> confirmed XSS findings
    sqlmap.txt         -> SQL injection scan results

Each template uses the placeholder `{target}` (e.g. "example.com") which the
project creation flow substitutes with the user's actual target.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict


# --- Template content -------------------------------------------------------

TARGET_TXT = "{target}\n"

ALL_SUBS_TXT = (
    "# All Subs - aggregated subdomain list (raw output of subfinder + subenum)\n"
    "# Populated by the recon agent. One hostname per line.\n"
    "#\n"
    "# Example commands (run inside the project folder):\n"
    "#   subfinder -dL target.txt -all -recursive -o Subs01.txt\n"
    "#   subenum   -l target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o Subs02.txt\n"
    "#   cat Subs*.txt | anew | tee AllSubs.txt\n"
    "{target}\n"
)

ALIVE_SUBS_TXT = (
    "# Alive Subs - live, responsive subdomains (httpx probed)\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat AllSubs.txt | httpx -o AliveSubs.txt\n"
    "https://{target}\n"
)

URLS_TXT = (
    "# urls.txt - all archived URLs (Wayback Machine, gau, katana)\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat AliveSubs.txt | waybackurls | tee urls.txt\n"
    "https://{target}/\n"
)

PARAM_TXT = (
    "# param.txt - URLs that contain query parameters (=), used for SQLi / XSS / SSRF testing\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat urls.txt | grep '=' | tee param.txt\n"
    "https://{target}/?q=test\n"
)

JS_TXT = (
    "# js.txt - JavaScript files discovered (often leak endpoints, keys, logic)\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat urls.txt | grep -iE '.js' | grep -ivE '.json' | sort -u | tee js.txt\n"
    "https://{target}/static/js/app.js\n"
)

XSS_TXT = (
    "# xss.txt - candidate XSS URLs (filtered by gf xss pattern)\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat urls.txt | uro | gf xss > xss.txt\n"
    "https://{target}/?q=<script>alert(1)</script>\n"
)

LFI_TXT = (
    "# lfi.txt - candidate Local File Inclusion URLs (filtered by gf lfi pattern)\n"
    "# Populated by the recon agent. One URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   cat AliveSubs.txt | gau | uro | gf lfi | tee lfi.txt\n"
    "https://{target}/?file=../../../etc/passwd\n"
)

XSS_VULNERABLE_TXT = (
    "# XSSvulnerable.txt - confirmed XSS findings (Dalfox output)\n"
    "# Populated by the recon agent. One confirmed URL per line.\n"
    "#\n"
    "# Example command:\n"
    "#   dalfox file xss.txt | tee XSSvulnerable.txt\n"
    "# (no findings yet - Dalfox will append here as it runs)\n"
)

SQLMAP_TXT = (
    "# sqlmap.txt - SQL injection scan results\n"
    "# Populated by the recon agent.\n"
    "#\n"
    "# Example command:\n"
    "#   sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt\n"
    "# (no findings yet - sqlmap will append here as it runs)\n"
)


# --- File map ---------------------------------------------------------------

TEMPLATES: Dict[str, str] = {
    "target.txt":         TARGET_TXT,
    "AllSubs.txt":        ALL_SUBS_TXT,
    "AliveSubs.txt":      ALIVE_SUBS_TXT,
    "urls.txt":           URLS_TXT,
    "param.txt":          PARAM_TXT,
    "js.txt":             JS_TXT,
    "xss.txt":            XSS_TXT,
    "lfi.txt":            LFI_TXT,
    "XSSvulnerable.txt":  XSS_VULNERABLE_TXT,
    "sqlmap.txt":         SQLMAP_TXT,
}


# --- Public API -------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{target\}")


def seed_empty_folder(folder: Path, target: str = "example.com") -> list[str]:
    """Write the ten recon template files into `folder`.

    - Only writes files that don't already exist (never clobbers user data).
    - Replaces the ``{target}`` placeholder with `target` everywhere.
    - Returns the list of filenames that were created.
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    for name, body in TEMPLATES.items():
        path = folder / name
        if path.exists():
            continue
        rendered = _PLACEHOLDER.sub(target, body)
        path.write_text(rendered, encoding="utf-8")
        created.append(name)
    return created


def list_templates() -> list[str]:
    """Return the list of template filenames in canonical order."""
    return list(TEMPLATES.keys())
