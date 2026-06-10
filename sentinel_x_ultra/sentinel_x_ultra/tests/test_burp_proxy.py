"""
Unit tests for BurpProxyAnalyzer cache functionality.
Tests that request data persists correctly across API calls.
"""

import pytest
from sentinel_x_ultra.burp_proxy import (
    BurpProxyAnalyzer, 
    clear_all_burp_caches, 
    get_cached_proxy_count,
    _burp_proxy_cache
)


class TestBurpProxyAnalyzerCache:
    """Tests for BurpProxyAnalyzer caching mechanism"""
    
    def setup_method(self):
        """Clear cache before each test"""
        clear_all_burp_caches()
    
    def teardown_method(self):
        """Clear cache after each test"""
        clear_all_burp_caches()
    
    def test_analyzer_creates_cache_entry(self):
        """Test that creating an analyzer adds it to the cache"""
        analyzer = BurpProxyAnalyzer("http://localhost:8080")
        assert "http://localhost:8080" in _burp_proxy_cache
        assert get_cached_proxy_count() == 1
    
    def test_same_proxy_reuses_analyzer(self):
        """Test that same proxy URL reuses existing analyzer"""
        analyzer1 = BurpProxyAnalyzer("http://localhost:8080")
        request_count_before = len(analyzer1.requests)
        
        # Simulate adding a request
        analyzer1.requests.append({"url": "/test", "method": "GET"})
        
        # Create second analyzer with same proxy - should reuse
        analyzer2 = BurpProxyAnalyzer("http://localhost:8080")
        
        # Both should see the same requests list
        assert analyzer2.requests == analyzer1.requests
        assert len(analyzer2.requests) == request_count_before + 1
    
    def test_different_proxies_separate_analyzers(self):
        """Test that different proxy URLs get separate analyzers"""
        analyzer1 = BurpProxyAnalyzer("http://localhost:8080")
        analyzer1.requests.append({"url": "/test1", "method": "GET"})
        
        analyzer2 = BurpProxyAnalyzer("http://localhost:9090")
        analyzer2.requests.append({"url": "/test2", "method": "POST"})
        
        assert analyzer1.requests != analyzer2.requests
        assert len(analyzer1.requests) == 1
        assert len(analyzer2.requests) == 1
        assert get_cached_proxy_count() == 2
    
    def test_clear_removes_from_cache(self):
        """Test that clear() removes analyzer from cache"""
        analyzer = BurpProxyAnalyzer("http://localhost:8080")
        assert "http://localhost:8080" in _burp_proxy_cache
        
        analyzer.clear()
        
        assert "http://localhost:8080" not in _burp_proxy_cache
        assert get_cached_proxy_count() == 0
    
    def test_clear_all_clears_everything(self):
        """Test that clear_all_burp_caches clears entire cache"""
        BurpProxyAnalyzer("http://localhost:8080")
        BurpProxyAnalyzer("http://localhost:9090")
        BurpProxyAnalyzer("http://other:8888")
        
        assert get_cached_proxy_count() == 3
        
        clear_all_burp_caches()
        
        assert get_cached_proxy_count() == 0
    
    def test_data_persistence_across_get_summary(self):
        """Test that request data persists when calling get_summary"""
        analyzer = BurpProxyAnalyzer("http://localhost:8080")
        
        # Add some requests
        analyzer.requests.extend([
            {"url": "/api/users", "method": "GET", "is_api_endpoint": True},
            {"url": "/api/login", "method": "POST", "is_auth_endpoint": True},
        ])
        analyzer.findings.extend([
            {"type": "sql_injection", "severity": "high"}
        ])
        
        # Create new analyzer reference (simulating separate API call)
        analyzer2 = BurpProxyAnalyzer("http://localhost:8080")
        
        # get_summary should see accumulated data
        summary = analyzer2.get_summary()
        
        assert summary["total_requests"] == 2
        assert summary["api_endpoints"] == 1
        assert summary["auth_endpoints"] == 1
        assert summary["total_findings"] == 1
        assert summary["high_findings"] == 1


class TestBurpProxyAnalyzerAnalysis:
    """Tests for BurpProxyAnalyzer request analysis"""
    
    def setup_method(self):
        """Clear cache before each test"""
        clear_all_burp_caches()
    
    def teardown_method(self):
        """Clear cache after each test"""
        clear_all_burp_caches()
    
    @pytest.mark.asyncio
    async def test_analyze_request_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_request(
            method="GET",
            url="/api/users?id=1' OR '1'='1",
            headers={},
            body=None
        )
        
        assert len(result["findings"]) >= 1
        assert any(f["type"] == "sql_injection" for f in result["findings"])
    
    @pytest.mark.asyncio
    async def test_analyze_request_xss_detection(self):
        """Test XSS pattern detection"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_request(
            method="POST",
            url="/api/search",
            headers={},
            body="<script>alert('xss')</script>"
        )
        
        assert len(result["findings"]) >= 1
        assert any(f["type"] == "xss" for f in result["findings"])
    
    @pytest.mark.asyncio
    async def test_analyze_request_ssrf_detection(self):
        """Test SSRF pattern detection"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_request(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/",
            headers={},
            body=None
        )
        
        assert len(result["findings"]) >= 1
        assert any(f["type"] == "ssrf" for f in result["findings"])
    
    @pytest.mark.asyncio
    async def test_analyze_request_identifies_api_endpoint(self):
        """Test that API endpoints are correctly identified"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_request(
            method="GET",
            url="/api/v1/users",
            headers={},
            body=None
        )
        
        assert result["is_api_endpoint"] == True
    
    @pytest.mark.asyncio
    async def test_analyze_request_identifies_auth_endpoint(self):
        """Test that auth endpoints are correctly identified"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_request(
            method="POST",
            url="/api/auth/login",
            headers={},
            body=None
        )
        
        assert result["is_auth_endpoint"] == True
    
    def test_check_sensitive_data_password(self):
        """Test sensitive data detection for passwords"""
        analyzer = BurpProxyAnalyzer()
        
        result = analyzer._check_sensitive_data(
            body='{"password": "secret123"}',
            headers={}
        )
        
        assert result == True
    
    def test_check_sensitive_data_no_sensitive(self):
        """Test that normal data is not flagged"""
        analyzer = BurpProxyAnalyzer()
        
        result = analyzer._check_sensitive_data(
            body='{"name": "John", "age": 30}',
            headers={}
        )
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_analyze_response_error_codes(self):
        """Test error response detection"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_response(
            url="http://example.com/api/users",
            status_code=500,
            headers={},
            body="Internal Server Error"
        )
        
        assert len(result["findings"]) >= 1
        assert any(f["type"] == "error_response" for f in result["findings"])
    
    @pytest.mark.asyncio
    async def test_analyze_response_missing_security_headers(self):
        """Test missing security header detection"""
        analyzer = BurpProxyAnalyzer()
        
        result = await analyzer.analyze_response(
            url="http://example.com/",
            status_code=200,
            headers={},
            body="<html>Hello</html>"
        )
        
        assert any(f["type"] == "missing_security_header" for f in result["findings"])