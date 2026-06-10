"""
Sentinel-X Reconnaissance Methodology for Agents

This module contains the reconnaissance methodology derived from the bug bounty guide.
Agents should use this knowledge when performing reconnaissance tasks.

METHODOLOGY SUMMARY:
====================

Phase 1: Google Dorking
-----------------------
Use BigBountyRecon with 58 different techniques:
- site:*.domain.com inurl:"*admin | login" | inurl:.php | .asp (find login pages)
- site:*.domain.com intext:sql syntax near | intext:syntax error... (find SQLi)
- site:*.domain.com inurl:/geoserver/ows?service=wfs (find exposed services)

Phase 2: Subdomain Enumeration
------------------------------
1. echo domain.com > target.txt
2. subfinder -dL target.txt -all -recursive -o Subs01.txt
3. subenum -l target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o Subs02.txt
4. cat Subs*.txt | anew | tee AllSubs.txt
5. cat AllSubs.txt | httpx -o AliveSubs.txt

Phase 3: URL Collection
-----------------------
1. cat AliveSubs.txt | waybackurls | tee urls.txt
2. cat urls.txt | grep '=' | tee param.txt (for SQLi/XSS testing)
3. cat urls.txt | grep -iE '.js'|grep -ivE '.json'|sort -u | tee js.txt

Phase 4: Vulnerability Scanning
-------------------------------
1. nuclei -list urls.txt -t /fuzzing-templates
2. nuclei -list AliveSubs.txt -t /nuclei-templates/vulnerabilities -t /nuclei-templates/cves

Phase 5: XSS Testing
--------------------
1. cat urls.txt | uro | gf xss > xss.txt
2. dalfox file xss.txt | tee XSSvulnerable.txt

Phase 6: LFI Detection
----------------------
1. cat AliveSubs.txt | gau | uro | gf lfi | tee lfi.txt
2. nuclei -list target.txt -tags lfi

Phase 7: SQL Injection Testing
------------------------------
1. python3 sqlifinder.py -d domain.com
2. sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

Phase 8: Open Redirect Detection
--------------------------------
1. cat urls.txt | grep -a -i =http | qsreplace 'evil.com' | while read host; do curl -s -L $host -I| grep evil.com && echo $host; done

Phase 9: CORS Testing
--------------------
1. site=$(cat target.txt); gau $site | while read url; do target=$(curl -sIH Origin: https://evil.com -X GET $url) | if grep 'https://evil.com'; then echo $url; fi; done

TOOL INTEGRATION:
=================
- BigBountyRecon: Google Dorking (58 techniques)
- SubFinder: Passive subdomain discovery
- SubEnum: Multi-source enumeration
- WaybackUrls: Historical URL collection
- Gau: Alternative URL collector
- Httpx: HTTP probing for alive hosts
- Dalfox: XSS vulnerability scanning
- Sqlifinder: SQL injection discovery
- Nuclei: Vulnerability scanning with templates
- Uro: URL filtering and deduplication
- Gf: Pattern matching for vulnerabilities

GITHUB LINKS:
=============
- https://github.com/Viralmaniar/BigBountyRecon
- https://github.com/projectdiscovery/subfinder
- https://github.com/bing0o/SubEnum
- https://github.com/tomnomnom/waybackurls
- https://github.com/hahwul/dalfox
- https://github.com/americo/sqlifinder
"""

RECON_METHODOLOGY = """
BUG BOUNTY RECONNAISSANCE METHODOLOGY (v1.0)
============================================

This methodology guides automated reconnaissance for bug bounty hunting.

TARGET SCOPING:
---------------
1. Define target domain(s)
2. Identify in-scope assets
3. Note out-of-scope boundaries

GOOGLE DORKING:
---------------
Use BigBountyRecon for initial reconnaissance:
- Login pages: site:*.target.com inurl:"admin | login" inurl:.php
- SQL Errors: site:*.target.com intext:"sql syntax error"
- Exposed services: site:*.target.com inurl:"/geoserver/ows"

SUBDOMAIN ENUMERATION:
----------------------
Step 1: Create target file
  echo target.com > targets.txt

Step 2: Passive enumeration (SubFinder)
  subfinder -dL targets.txt -all -recursive -o subfinder_results.txt

Step 3: Multi-source enumeration (SubEnum)
  subenum -l targets.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o subenum_results.txt

Step 4: Combine and dedupe
  cat subfinder_results.txt subenum_results.txt | anew | tee all_subdomains.txt

Step 5: Check which are alive
  cat all_subdomains.txt | httpx -o alive_hosts.txt

URL COLLECTION:
---------------
Step 1: Historical URLs (Wayback)
  cat alive_hosts.txt | waybackurls | tee urls.txt

Step 2: Extract parameters
  cat urls.txt | grep '=' | tee params.txt

Step 3: Extract JS files
  cat urls.txt | grep -iE '.js$' | grep -ivE '.json' | tee js_files.txt

VULNERABILITY SCANNING:
-----------------------
Step 1: General fuzzing
  nuclei -list urls.txt -t /fuzzing-templates

Step 2: Specific CVE scanning
  nuclei -list alive_hosts.txt -t /nuclei-templates/vulnerabilities -t /nuclei-templates/cves

XSS TESTING:
------------
Step 1: Filter XSS patterns
  cat urls.txt | uro | gf xss > xss_urls.txt

Step 2: Scan with Dalfox
  dalfox file xss_urls.txt -o xss_findings.txt

SQL INJECTION:
--------------
Step 1: Discovery
  python3 sqlifinder.py -d target.com

Step 2: Deep testing
  sqlmap -m params.txt --batch --random-agent --level 2

LFI DETECTION:
--------------
Step 1: Filter LFI patterns
  cat alive_hosts.txt | gau | uro | gf lfi > lfi_urls.txt

Step 2: Scan
  nuclei -list lfi_urls.txt -tags lfi

OPEN REDIRECT:
--------------
Step 1: Filter redirect patterns
  cat urls.txt | grep -a -i =http | qsreplace 'https://evil.com' > redirect_test.txt

Step 2: Test each URL
  while read url; do if curl -sL "$url" -I | grep -q 'evil.com'; then echo "VULN: $url"; fi; done < redirect_test.txt

CORS VULNERABILITIES:
---------------------
Step 1: Test with arbitrary origin
  gau target.com | while read url; do curl -sIH "Origin: https://evil.com" "$url" | grep -i "access-control"; done

TOOL PATHS (auto-installed to ~/.sentinelx/tools/):
---------------------------------------------------
- subfinder: ~/.sentinelx/tools/ or $GOPATH/bin
- waybackurls: ~/.sentinelx/tools/ or $GOPATH/bin
- httpx: ~/.sentinelx/tools/ or $GOPATH/bin
- nuclei: ~/.sentinelx/tools/ or $GOPATH/bin
- dalfox: ~/.sentinelx/tools/ or $GOPATH/bin
- gau: ~/.sentinelx/tools/ or $GOPATH/bin
- BigBountyRecon: ~/.sentinelx/tools/BigBountyRecon/
- SubEnum: ~/.sentinelx/tools/SubEnum/
- sqlifinder: ~/.sentinelx/tools/sqlifinder/

NUCLEI TEMPLATES:
-----------------
Default path: ~/nuclei-templates/
Templates: vulnerabilities/, cves/, fuzzing-templates/, exposures/

SEQUENTIAL WORKFLOW:
--------------------
1. Google Dorking (BigBountyRecon)
2. Subdomain Enum (SubFinder + SubEnum)
3. HTTP Probing (httpx - alive hosts only)
4. URL Collection (waybackurls + gau)
5. Parameter Extraction (grep '=')
6. Vulnerability Scan (nuclei)
7. XSS Testing (dalfox)
8. SQLi Testing (sqlifinder + sqlmap)
9. LFI Testing (gf + nuclei)
10. Report findings
"""

def get_recon_methodology() -> str:
    """Return the complete reconnaissance methodology for agent use."""
    return RECON_METHODOLOGY

def get_tool_info() -> dict:
    """Return information about integrated reconnaissance tools."""
    return {
        "bigbountyrecon":
        "subfinder": {
            "name": "SubFinder",
            "github": "https://github.com/projectdiscovery/subfinder",
            "purpose": "Passive subdomain enumeration",
            "installed_path": "$GOPATH/bin/subfinder",
        },
        "subenum": {
            "name": "SubEnum",
            "github": "https://github.com/bing0o/SubEnum",
            "purpose": "Multi-source subdomain enumeration",
            "installed_path": "~/.sentinelx/tools/SubEnum/",
        },
        "waybackurls": {
            "name": "WaybackUrls",
            "github": "https://github.com/tomnomnom/waybackurls",
            "purpose": "Historical URL collection",
            "installed_path": "$GOPATH/bin/waybackurls",
        },
        "gau": {
            "name": "Gau",
            "github": "https://github.com/lc/gau",
            "purpose": "Alternative URL collector",
            "installed_path": "$GOPATH/bin/gau",
        },
        "httpx": {
            "name": "Httpx",
            "github": "https://github.com/projectdiscovery/httpx",
            "purpose": "HTTP probing for alive hosts",
            "installed_path": "$GOPATH/bin/httpx",
        },
        "dalfox": {
            "name": "Dalfox",
            "github": "https://github.com/hahwul/dalfox",
            "purpose": "XSS vulnerability scanning",
            "installed_path": "$GOPATH/bin/dalfox",
        },
        "sqlifinder": {
            "name": "Sqlifinder",
            "github": "https://github.com/americo/sqlifinder",
            "purpose": "SQL injection discovery",
            "installed_path": "~/.sentinelx/tools/sqlifinder/",
        },
        "nuclei": {
            "name": "Nuclei",
            "github": "https://github.com/projectdiscovery/nuclei",
            "purpose": "Vulnerability scanning based on templates",
            "installed_path": "$GOPATH/bin/nuclei",
            "templates": "~/nuclei-templates/",
        },
    }