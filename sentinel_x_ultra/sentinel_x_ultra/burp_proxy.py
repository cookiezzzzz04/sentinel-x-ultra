"""
Burp Suite Proxy Integration for Community Edition
SENTINEL-X can act as an upstream proxy to Burp Suite Community to analyze traffic in real-time
"""

import asyncio
import json
from typing import Optional, List, Dict, Any
from datetime import datetime


# Module-level cache for persistent request tracking across endpoint calls
_burp_proxy_cache: Dict[str, "BurpProxyAnalyzer"] = {}


class BurpProxyAnalyzer:
    """Analyzes HTTP traffic by acting as an upstream proxy to Burp Suite"""
    
    def __init__(self, upstream_proxy: str = "http://localhost:8080"):
        self.upstream_proxy = upstream_proxy
        self.requests: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        
        # Check if we have an existing analyzer for this proxy
        global _burp_proxy_cache
        if upstream_proxy in _burp_proxy_cache:
            # Reuse existing analyzer to maintain accumulated data
            existing = _burp_proxy_cache[upstream_proxy]
            self.requests = existing.requests
            self.findings = existing.findings
        else:
            _burp_proxy_cache[upstream_proxy] = self
    
    async def analyze_request(self, method: str, url: str, headers: Dict, body: str = None) -> Dict[str, Any]:
        """Analyze a single request for security issues"""
        findings = []
        
        # Check for SQL injection patterns
        sql_patterns = ["'", " UNION ", " DROP ", "--", ";--", "1=1", "admin'"]
        for pattern in sql_patterns:
            if pattern.lower() in url.lower() or (body and pattern.lower() in body.lower()):
                findings.append({
                    "type": "sql_injection",
                    "severity": "high",
                    "pattern": pattern,
                    "location": "url" if pattern in url.lower() else "body",
                    "description": f"Potential SQL injection pattern detected: {pattern}"
                })
        
        # Check for XSS patterns
        xss_patterns = ["<script", "<img", "javascript:", "onerror=", "onload=", "alert("]
        for pattern in xss_patterns:
            if pattern.lower() in url.lower() or (body and pattern.lower() in body.lower()):
                findings.append({
                    "type": "xss",
                    "severity": "high",
                    "pattern": pattern,
                    "location": "url" if pattern in url.lower() else "body",
                    "description": f"Potential XSS pattern detected: {pattern}"
                })
        
        # Check for path traversal
        path_patterns = ["../", "..\\", "%2e%2e", "etc/passwd", "windows/system32"]
        for pattern in path_patterns:
            if pattern.lower() in url.lower():
                findings.append({
                    "type": "path_traversal",
                    "severity": "medium",
                    "pattern": pattern,
                    "location": "url",
                    "description": f"Potential path traversal pattern detected: {pattern}"
                })
        
        # Check for SSRF patterns
        ssrf_patterns = ["169.254.169.254", "localhost", "metadata.google", "10.0.0.", "127.0.0.1"]
        for pattern in ssrf_patterns:
            if pattern in url.lower():
                findings.append({
                    "type": "ssrf",
                    "severity": "critical",
                    "pattern": pattern,
                    "location": "url",
                    "description": f"Potential SSRF target detected: {pattern}"
                })
        
        # Check for API endpoints
        api_indicators = ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/graphql"]
        is_api = any(indicator in url.lower() for indicator in api_indicators)
        
        # Check for auth-related endpoints
        auth_indicators = ["/login", "/auth", "/token", "/signin", "/oauth", "/verify"]
        is_auth = any(indicator in url.lower() for indicator in auth_indicators)
        
        result = {
            "method": method,
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings,
            "is_api_endpoint": is_api,
            "is_auth_endpoint": is_auth,
            "has_sensitive_data": self._check_sensitive_data(body, headers)
        }
        
        self.requests.append(result)
        self.findings.extend(findings)
        
        return result
    
    def _check_sensitive_data(self, body: Optional[str], headers: Dict) -> bool:
        """Check if request contains sensitive data"""
        sensitive_keys = ["password", "token", "secret", "api_key", "auth", "credential"]
        
        if body:
            for key in sensitive_keys:
                if key.lower() in body.lower():
                    return True
        
        for key in headers.keys():
            if any(s in key.lower() for s in sensitive_keys):
                return True
        
        return False
    
    async def analyze_response(self, url: str, status_code: int, headers: Dict, body: str = None) -> Dict[str, Any]:
        """Analyze a response for security issues"""
        findings = []
        
        # Check for error responses
        if status_code >= 400:
            findings.append({
                "type": "error_response",
                "severity": "medium" if status_code < 500 else "high",
                "status_code": status_code,
                "description": f"Error response detected: {status_code}"
            })
        
        # Check for missing security headers
        required_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
        for header in required_headers:
            if header not in headers:
                findings.append({
                    "type": "missing_security_header",
                    "severity": "low",
                    "header": header,
                    "description": f"Recommended security header missing: {header}"
                })
        
        # Check for sensitive data exposure
        sensitive_patterns = ["password", "token", "api_key", "secret", "credential"]
        if body:
            for pattern in sensitive_patterns:
                if pattern.lower() in body.lower() and pattern.lower() not in url.lower():
                    findings.append({
                        "type": "sensitive_data_exposure",
                        "severity": "high",
                        "pattern": pattern,
                        "description": "Potential sensitive data exposed in response"
                    })
        
        return {
            "url": url,
            "status_code": status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary"""
        return {
            "total_requests": len(self.requests),
            "total_findings": len(self.findings),
            "api_endpoints": sum(1 for r in self.requests if r.get("is_api_endpoint")),
            "auth_endpoints": sum(1 for r in self.requests if r.get("is_auth_endpoint")),
            "critical_findings": len([f for f in self.findings if f.get("severity") == "critical"]),
            "high_findings": len([f for f in self.findings if f.get("severity") == "high"]),
            "findings_by_type": self._count_by_type(self.findings)
        }
    
    def _count_by_type(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            type_ = f.get("type", "unknown")
            counts[type_] = counts.get(type_, 0) + 1
        return counts
    
    def clear(self):
        """Clear all stored requests and findings"""
        self.requests = []
        self.findings = []
        global _burp_proxy_cache
        if self.upstream_proxy in _burp_proxy_cache:
            del _burp_proxy_cache[self.upstream_proxy]


def clear_all_burp_caches():
    """Clear all cached BurpProxyAnalyzer instances to prevent memory leaks"""
    global _burp_proxy_cache
    _burp_proxy_cache.clear()


def get_cached_proxy_count() -> int:
    """Return the number of cached proxy analyzers"""
    return len(_burp_proxy_cache)