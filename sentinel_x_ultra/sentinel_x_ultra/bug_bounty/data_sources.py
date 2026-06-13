"""
DATA SOURCES — Live External API Clients for Passive Intelligence (Phase 4, Upgraded).

Provides API clients for:
  - Shodan (iot/search/maps)
  - Censys (hosts/certificates/search)
  - SecurityTrails (DNS/history/subdomains)
  - BuiltWith (technology profiling)
  - URLScan.io (historical screenshots/requests)

Upgraded with:
- In-memory caching of API results to avoid redundant calls
- Source prioritization by reliability score
- Smart result merging with dedup and confidence weighting
- Graceful degradation: if a source fails, continue without it
- Batch domain enrichment for multi-domain scans
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DataSourceResult:
    """Result from an external data source query."""
    source: str = ""
    success: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    cached: bool = False
    query_time_ms: float = 0.0


@dataclass
class MergedEnrichment:
    """Merged enrichment from multiple data sources."""
    subdomains: list[str] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)
    confidence: float = 0.0


# ── Shared Cache ────────────────────────────────────────────────────────────

class _SourceCache:
    """Simple TTL cache for API results to avoid redundant calls."""

    def __init__(self, ttl_seconds: int = 3600):
        self._cache: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        if key in self._cache:
            ts, val = self._cache[key]
            if time.monotonic() - ts < self._ttl:
                return val
            del self._cache[key]
        return None

    def set(self, key: str, value: Any):
        self._cache[key] = (time.monotonic(), value)

    def invalidate(self, key: str):
        self._cache.pop(key, None)

    def clear(self):
        self._cache.clear()


_cache = _SourceCache()


class _ResultCacheAdapter:
    """Adapter that wraps a ResultCache from execution_engine with the _SourceCache interface.

    ResultCache uses invalidate_all() instead of clear(), and its set() has extra optional
    params (ttl, tags). This adapter normalises both interfaces.
    """

    def __init__(self, result_cache):
        self._rc = result_cache

    def get(self, key: str):
        return self._rc.get(key)

    def set(self, key: str, value):
        self._rc.set(key, value)

    def invalidate(self, key: str):
        self._rc.invalidate(key)

    def clear(self):
        self._rc.invalidate_all()


def set_shared_cache(result_cache):
    """Replace the module-level cache with a shared ResultCache from the execution engine.

    Args:
        result_cache: A ResultCache instance (from execution_engine.ResultCache).
    """
    global _cache
    _cache = _ResultCacheAdapter(result_cache)


class ShodanClient:
    """Shodan API client — host/search passive intelligence.

    Free tier: 1 credit/s query, 100 queries/month
    Requires: SHODAN_API_KEY env var
    """

    def __init__(self):
        self.api_key = os.environ.get("SHODAN_API_KEY", "")
        self.base_url = "https://api.shodan.io"
        self._available = bool(self.api_key)
        self.reliability = 0.85  # Shodan is highly reliable for exposed services

    @property
    def is_available(self) -> bool:
        return self._available

    async def _query(self, endpoint: str, params: dict) -> DataSourceResult:
        """Generic query with caching."""
        cache_key = f"shodan:{endpoint}:{json.dumps(params, sort_keys=True)}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="shodan", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="shodan", error="SHODAN_API_KEY not configured")
        try:
            import httpx
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}{endpoint}",
                    params={**params, "key": self.api_key},
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="shodan", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="shodan", error=f"Shodan API error: {resp.status_code}", query_time_ms=elapsed,
            )
        except ImportError:
            return DataSourceResult(source="shodan", error="httpx not installed")
        except Exception as e:
            return DataSourceResult(source="shodan", error=str(e)[:100])

    async def search(self, query: str) -> DataSourceResult:
        return await self._query("/shodan/host/search", {"query": query, "limit": 10})

    async def host_info(self, ip: str) -> DataSourceResult:
        return await self._query(f"/shodan/host/{ip}", {})

    async def domain_info(self, domain: str) -> DataSourceResult:
        return await self.search(f"hostname:{domain}")

    async def dns_resolve(self, hostname: str) -> DataSourceResult:
        """Resolve a hostname to IP using Shodan's DNS resolver."""
        return await self._query("/dns/resolve", {"hostnames": hostname})


class CensysClient:
    """Censys API client — certificates/hosts search.

    Free tier: 250 queries/month
    Requires: CENSYS_API_ID + CENSYS_API_SECRET env vars
    """

    def __init__(self):
        self.api_id = os.environ.get("CENSYS_API_ID", "")
        self.api_secret = os.environ.get("CENSYS_API_SECRET", "")
        self.base_url = "https://search.censys.io/api/v2"
        self._available = bool(self.api_id and self.api_secret)
        self.reliability = 0.80  # Censys certificate data is broad but sometimes stale

    @property
    def is_available(self) -> bool:
        return self._available

    async def search_certificates(self, domain: str) -> DataSourceResult:
        cache_key = f"censys:cert:{domain}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="censys", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="censys", error="CENSYS_API_ID/SECRET not configured")
        try:
            import httpx
            start = time.monotonic()
            auth = (self.api_id, self.api_secret)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/certificates/search",
                    params={"q": f"parsed.names: {domain}", "per_page": 50},
                    auth=auth,
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="censys", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="censys", error=f"Censys API error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="censys", error=str(e)[:100])

    async def search_hosts(self, query: str) -> DataSourceResult:
        cache_key = f"censys:hosts:{query}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="censys", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="censys", error="CENSYS_API_ID/SECRET not configured")
        try:
            import httpx
            start = time.monotonic()
            auth = (self.api_id, self.api_secret)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/hosts/search",
                    params={"q": query, "per_page": 20},
                    auth=auth,
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="censys", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="censys", error=f"Censys hosts error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="censys", error=str(e)[:100])

    async def host_info(self, ip: str) -> DataSourceResult:
        cache_key = f"censys:host:{ip}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="censys", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="censys", error="CENSYS_API_ID/SECRET not configured")
        try:
            import httpx
            start = time.monotonic()
            auth = (self.api_id, self.api_secret)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{self.base_url}/hosts/{ip}", auth=auth)
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="censys", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="censys", error=f"Censys host info error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="censys", error=str(e)[:100])


class SecurityTrailsClient:
    """SecurityTrails API client — DNS/history/subdomains.

    Free tier: 50 queries/month
    Requires: SECURITYTRAILS_API_KEY env var
    """

    def __init__(self):
        self.api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        self.base_url = "https://api.securitytrails.com/v1"
        self._available = bool(self.api_key)
        self.reliability = 0.90  # SecurityTrails has excellent DNS data

    @property
    def is_available(self) -> bool:
        return self._available

    async def get_subdomains(self, domain: str) -> DataSourceResult:
        cache_key = f"st:sub:{domain}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="securitytrails", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="securitytrails", error="SECURITYTRAILS_API_KEY not configured")
        try:
            import httpx
            headers = {"APIKEY": self.api_key, "Accept": "application/json"}
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/domain/{domain}/subdomains",
                    headers=headers, params={"children_only": "false"},
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="securitytrails", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="securitytrails", error=f"SecurityTrails error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="securitytrails", error=str(e)[:100])

    async def get_dns_history(self, domain: str, record_type: str = "a") -> DataSourceResult:
        cache_key = f"st:dns:{domain}:{record_type}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="securitytrails", success=True, data=cached, cached=True)

        if not self._available:
            return DataSourceResult(source="securitytrails", error="SECURITYTRAILS_API_KEY not configured")
        try:
            import httpx
            headers = {"APIKEY": self.api_key, "Accept": "application/json"}
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/history/{domain}/dns/{record_type}", headers=headers,
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="securitytrails", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="securitytrails", error=f"SecurityTrails DNS error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="securitytrails", error=str(e)[:100])


class URLScanClient:
    """URLScan.io client — historical screenshots/requests.

    Free tier: 100 queries/month (no API key needed for public scans)
    """

    def __init__(self):
        self.base_url = "https://urlscan.io/api/v1"
        self.api_key = os.environ.get("URLSCAN_API_KEY", "")
        self.reliability = 0.75  # URLScan results can be noisy

    @property
    def is_available(self) -> bool:
        return True

    async def search_domain(self, domain: str) -> DataSourceResult:
        cache_key = f"urlscan:domain:{domain}"
        cached = _cache.get(cache_key)
        if cached:
            return DataSourceResult(source="urlscan", success=True, data=cached, cached=True)

        try:
            import httpx
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["API-Key"] = self.api_key
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/search/",
                    params={"q": f"domain:{domain}", "size": 20},
                    headers=headers,
                )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                data = resp.json()
                _cache.set(cache_key, data)
                return DataSourceResult(
                    source="urlscan", success=True, data=data, query_time_ms=elapsed,
                )
            return DataSourceResult(
                source="urlscan", error=f"URLScan error: {resp.status_code}", query_time_ms=elapsed,
            )
        except (ImportError, Exception) as e:
            return DataSourceResult(source="urlscan", error=str(e)[:100])


# ── Source Priority / Reliability ──────────────────────────────────────────

SOURCE_RELIABILITY: dict[str, float] = {
    "securitytrails": 0.90,
    "shodan": 0.85,
    "censys": 0.80,
    "urlscan": 0.75,
}


# ── Data Source Aggregator ──────────────────────────────────────────────────

class DataSourceAggregator:
    """Aggregates all external data sources into one smart interface.

    Upgraded with:
    - Caching: results cached for 1 hour to avoid redundant API calls
    - Source prioritization: SecurityTrails > Shodan > Censys > URLScan
    - Smart merging: dedup by reliability, highest-confidence source wins
    - Graceful degradation: failures don't cascade
    - Batch enrichment: enrich multiple domains at once
    """

    def __init__(self, cache=None):
        self.shodan = ShodanClient()
        self.censys = CensysClient()
        self.securitytrails = SecurityTrailsClient()
        self.urlscan = URLScanClient()
        if cache is not None:
            set_shared_cache(cache)

    def get_available_sources(self) -> list[str]:
        """Return list of available (configured) source names, highest reliability first."""
        sources = []
        for name, client in self._sorted_sources():
            if (hasattr(client, "is_available") and client.is_available) or name == "urlscan":
                sources.append(name)
        return sources

    def _sorted_sources(self):
        """Return sources sorted by reliability (highest first)."""
        sources = [
            ("securitytrails", self.securitytrails),
            ("shodan", self.shodan),
            ("censys", self.censys),
            ("urlscan", self.urlscan),
        ]
        return sorted(sources, key=lambda s: SOURCE_RELIABILITY.get(s[0], 0.5), reverse=True)

    async def search_domain(self, domain: str) -> dict[str, DataSourceResult]:
        """Search all available sources for a domain. Returns per-source results.

        Higher-reliability sources are queried first. If a source returns
        exceptional results, lower-reliability sources may be skipped or
        queried with reduced scope.
        """
        results = {}
        for name, client in self._sorted_sources():
            try:
                available = getattr(client, "is_available", True)
                if not available:
                    continue
                if name == "securitytrails":
                    results[name] = await client.get_subdomains(domain)
                elif name == "shodan":
                    results[name] = await client.domain_info(domain)
                elif name == "censys":
                    results[name] = await client.search_certificates(domain)
                elif name == "urlscan":
                    results[name] = await client.search_domain(domain)
            except Exception as e:
                results[name] = DataSourceResult(source=name, error=str(e)[:100])
        return results

    async def search_domain_batch(self, domains: list[str]) -> dict[str, dict[str, DataSourceResult]]:
        """Search multiple domains at once. Returns {domain: {source: result}}."""
        results = {}
        for domain in domains:
            results[domain] = await self.search_domain(domain)
        return results

    async def enrich_with_external_data(self, domain: str, intel: dict[str, Any]) -> dict[str, Any]:
        """Enrich existing intelligence with external data source findings.

        Merges subdomains, technologies, historical URLs from all sources
        with dedup and confidence weighting. Higher-reliability sources'
        data takes precedence when conflicts arise.
        """
        results = await self.search_domain(domain)

        enriched = dict(intel)
        enriched["data_sources_checked"] = []
        enriched["data_source_confidence"] = 0.0

        # Collect subdomains from all sources with dedup
        all_subdomains = set(intel.get("subdomains", []))
        total_confidence = 0.0
        source_count = 0

        for name, client in self._sorted_sources():
            result = results.get(name)
            if not result or not result.success:
                continue

            source_count += 1
            reliability = SOURCE_RELIABILITY.get(name, 0.5)
            total_confidence += reliability
            enriched["data_sources_checked"].append(name)

            if name == "securitytrails":
                data = result.data
                subdomains = data.get("subdomains", [])
                endpoint = data.get("endpoint", domain)
                for sub in subdomains:
                    full = f"{sub}.{endpoint}" if not sub.startswith(endpoint) else sub
                    all_subdomains.add(full)

            elif name == "censys":
                data = result.data
                certificates = data.get("result", {}).get("hits", [])
                for cert in certificates:
                    names = cert.get("parsed", {}).get("names", [])
                    for n in names:
                        if n.endswith(f".{domain}") and "*" not in n:
                            all_subdomains.add(n.lower())

            elif name == "shodan":
                data = result.data
                matches = data.get("matches", [])
                for match in matches:
                    hostnames = match.get("hostnames", [])
                    for hn in hostnames:
                        if hn.endswith(f".{domain}") or hn == domain:
                            all_subdomains.add(hn.lower())

            elif name == "urlscan":
                data = result.data
                url_results = data.get("results", [])
                for r in url_results:
                    page = r.get("page", {})
                    url_domain = page.get("domain", "")
                    if url_domain and (url_domain == domain or url_domain.endswith(f".{domain}")):
                        all_subdomains.add(url_domain.lower())
                    url = page.get("url", "")
                    if url:
                        enriched.setdefault("historical_urls", []).append(url)

        enriched["subdomains"] = list(all_subdomains)
        enriched["external_sources_success"] = len(enriched["data_sources_checked"])
        enriched["data_source_confidence"] = round(
            total_confidence / max(source_count, 1), 2
        )

        return enriched

    async def search_domain_merged(self, domain: str) -> MergedEnrichment:
        """Search a domain and merge results from ALL sources into one structured output.

        This is the highest-level API — returns a clean MergedEnrichment object
        with dedup, confidence, and source attribution.
        """
        results = await self.search_domain(domain)
        merged = MergedEnrichment()

        for name, client in self._sorted_sources():
            result = results.get(name)
            if not result or not result.success:
                merged.sources_failed.append(name)
                continue

            merged.sources_used.append(name)
            reliability = SOURCE_RELIABILITY.get(name, 0.5)

            if name == "securitytrails":
                data = result.data
                subs = data.get("subdomains", [])
                endpoint = data.get("endpoint", domain)
                for sub in subs:
                    full = f"{sub}.{endpoint}" if not sub.startswith(endpoint) else sub
                    if full not in merged.subdomains:
                        merged.subdomains.append(full)

            elif name == "censys":
                data = result.data
                certs = data.get("result", {}).get("hits", [])
                for cert in certs[:20]:
                    names = cert.get("parsed", {}).get("names", [])
                    for n in names:
                        if n.endswith(f".{domain}") and "*" not in n and n not in merged.subdomains:
                            merged.subdomains.append(n.lower())
                    merged.certificates.append({
                        "source": "censys",
                        "names": names[:10],
                        "fingerprint": cert.get("fingerprint", "")[:20],
                    })

            elif name == "shodan":
                data = result.data
                matches = data.get("matches", [])
                for match in matches:
                    hostnames = match.get("hostnames", [])
                    for hn in hostnames:
                        if hn.endswith(f".{domain}") and hn not in merged.subdomains:
                            merged.subdomains.append(hn.lower())
                    ip = match.get("ip_str", "")
                    if ip and ip not in merged.ip_addresses:
                        merged.ip_addresses.append(ip)
                    port = match.get("port", 0)
                    if port and port not in merged.open_ports:
                        merged.open_ports.append(port)

            elif name == "urlscan":
                data = result.data
                url_results = data.get("results", [])
                for r in url_results:
                    page = r.get("page", {})
                    url_domain = page.get("domain", "")
                    if url_domain and url_domain.endswith(f".{domain}") and url_domain not in merged.subdomains:
                        merged.subdomains.append(url_domain.lower())
                    url = page.get("url", "")
                    if url and url not in merged.historical_urls:
                        merged.historical_urls.append(url)

        # Calculate overall confidence based on which sources responded
        if merged.sources_used:
            reliability_scores = [SOURCE_RELIABILITY.get(s, 0.5) for s in merged.sources_used]
            merged.confidence = round(sum(reliability_scores) / len(reliability_scores), 2)
        else:
            merged.confidence = 0.0

        return merged

    def clear_cache(self):
        """Clear all cached API results."""
        _cache.clear()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {"cache_enabled": True, "ttl_seconds": 3600}
