# ============ BURP SUITE INTEGRATION (Community Edition Support) ============

class BurpConnectRequest(BaseModel):
    proxy_url: str = "http://localhost:8080"
    api_key: str | None = None


class BurpHistoryRequest(BaseModel):
    proxy_url: str = "http://localhost:8080"
    api_key: str | None = None
    limit: int = 100


class BurpUploadRequest(BaseModel):
    """Request for Burp Suite JSON export upload."""
    burp_data: list[dict]  # The JSON export from Burp Suite
    format: str = "json"  # Currently only supports JSON format from Burp


@app.post("/api/burp/connect")
async def burp_connect(req: BurpConnectRequest):
    """Test connection to Burp Suite REST API (Professional only)."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    headers = {}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"

    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5)
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    try:
        test_url = f"{req.proxy_url.rstrip('/')}/v0.1/scan"
        response = session.get(test_url, headers=headers, timeout=5)

        if response.status_code == 200:
            return {"status": "ok", "message": "Connected to Burp Suite Professional successfully", "version": response.text.strip('"'), "edition": "professional"}
        elif response.status_code == 401:
            return {"status": "error", "error": "Authentication failed. Check your API key.", "edition": "professional"}
        else:
            return {"status": "error", "error": f"Unexpected response: {response.status_code}", "edition": "professional"}
    except requests.exceptions.ConnectionError:
        return {
            "status": "info",
            "edition": "community",
            "message": "Burp Suite Community Edition detected. Use 'Upload Export' to import your proxy history JSON file instead.",
            "hint": "In Burp Suite: Proxy > HTTP History > select items > Export > JSON format"
        }
    except requests.exceptions.Timeout:
        return {"status": "error", "error": "Connection timed out. Burp Suite may be unresponsive."}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/burp/upload")
async def burp_upload(req: BurpUploadRequest):
    """
    Upload and analyze Burp Suite JSON export file.

    Works with Burp Suite Community Edition!

    How to export from Burp Suite:
    1. Go to Proxy > HTTP History
    2. Select the requests you want to analyze (or Ctrl+A for all)
    3. Click "Export" button
    4. Choose format: JSON
    5. Save the file
    6. Upload that file here
    """
    try:
        burp_data = req.burp_data

        if not burp_data or len(burp_data) == 0:
            return {"status": "error", "error": "No data in uploaded file. Ensure you exported requests from Burp Suite."}

        findings = []
        api_endpoints = []
        auth_endpoints = []
        error_responses = []

        for item in burp_data:
            url = item.get("url", "")
            method = item.get("method", "GET").upper()
            response_code = item.get("responseCode", 0)

            # Detect API endpoints
            if "/api/" in url.lower() or "/rest/" in url.lower() or "/graphql" in url.lower():
                api_endpoints.append({"url": url, "method": method})

            # Detect auth-related endpoints
            if any(x in url.lower() for x in ["login", "auth", "token", "signin", "jwt", "session"]):
                auth_endpoints.append({"url": url, "method": method})

            # Detect error responses
            if response_code >= 400:
                error_responses.append({"url": url, "method": method, "code": response_code})

            # Analyze request/response for potential issues
            request = item.get("request", {})
            response = item.get("response", {})

            # Check for sensitive data exposure in responses
            if isinstance(response, dict):
                resp_str = str(response).lower()
                if any(x in resp_str for x in ["password", "token", "api_key", "secret", "credential"]):
                    findings.append({
                        "type": "sensitive_data",
                        "url": url,
                        "method": method,
                        "code": response_code,
                        "severity": "medium"
                    })

            # Check for missing security headers
            if isinstance(response, dict):
                headers = response.get("headers", {}) if isinstance(response.get("headers"), dict) else {}
                missing_headers = []
                if "x-frame-options" not in str(headers).lower():
                    missing_headers.append("X-Frame-Options")
                if "x-content-type-options" not in str(headers).lower():
                    missing_headers.append("X-Content-Type-Options")
                if "strict-transport-security" not in str(headers).lower():
                    missing_headers.append("HSTS")
                if missing_headers:
                    findings.append({
                        "type": "missing_security_headers",
                        "url": url,
                        "method": method,
                        "missing": missing_headers,
                        "severity": "low"
                    })

        # Generate summary
        summary = {
            "total_requests": len(burp_data),
            "api_endpoints": len(api_endpoints),
            "auth_endpoints": len(auth_endpoints),
            "error_responses": len(error_responses),
            "security_findings": len(findings),
            "high_severity": len([f for f in findings if f.get("severity") == "high" or f.get("severity") == "critical"]),
        }

        return {
            "status": "ok",
            "edition": "community",
            "message": f"Successfully analyzed {len(burp_data)} requests from Burp Suite export",
            "summary": summary,
            "findings": findings[:30],  # Limit to 30 findings
            "api_endpoints": api_endpoints[:20],
            "auth_endpoints": auth_endpoints[:10],
            "error_responses": error_responses[:20],
            "hints": [
                "Review API endpoints for proper authentication and authorization",
                "Check error responses for information disclosure",
                "Verify auth endpoints for secure credential handling"
            ]
        }

    except Exception as e:
        logger.error("burp_upload_error", error=str(e))
        return {"status": "error", "error": f"Failed to process Burp Suite export: {e!s}"}


@app.post("/api/burp/scan")
async def burp_scan(req: BurpHistoryRequest):
    """
    Analyze Burp Suite history (Professional REST API or fallback message).

    For Community Edition users, use /api/burp/upload instead.
    """
    import requests

    headers = {"Accept": "application/json"}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"

    try:
        history_url = f"{req.proxy_url.rstrip('/')}/v0.1/proxy/history"
        params = {"limit": req.limit}
        response = requests.get(history_url, headers=headers, params=params, timeout=10)

        if response.status_code != 200:
            return {
                "status": "info",
                "edition": "community",
                "message": "Burp Suite Community Edition detected. Please use the 'Upload JSON Export' option in the Input Sources panel.",
                "hint": "Proxy > HTTP History > Export > JSON format"
            }

        history = response.json() if response.headers.get("content-type", "").startswith("application/json") else []

        findings = []
        for item in (history if isinstance(history, list) else []):
            url = item.get("url", "")
            method = item.get("method", "GET")
            response_code = item.get("responseCode", 0)

            if response_code >= 400:
                findings.append({"type": "error_response", "url": url, "method": method, "code": response_code})
            if "/api/" in url.lower() or "/rest/" in url.lower():
                findings.append({"type": "api_endpoint", "url": url, "method": method})
            if "authorization" in str(item.get("request", {})).lower() or "bearer" in str(item.get("request", {})).lower():
                findings.append({"type": "auth_header_found", "url": url, "method": method})

        return {
            "status": "ok",
            "edition": "professional",
            "scan_summary": {
                "total_requests": len(history) if isinstance(history, list) else 0,
                "api_endpoints": len([f for f in findings if f["type"] == "api_endpoint"]),
                "error_responses": len([f for f in findings if f["type"] == "error_response"]),
                "auth_headers": len([f for f in findings if f["type"] == "auth_header_found"]),
            },
            "findings": findings[:20],
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "info",
            "edition": "community",
            "message": "Please use 'Upload JSON Export' for Burp Suite Community Edition",
            "hint": "In Burp Suite: Proxy > HTTP History > Export > JSON format"
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/burp/formats")
async def burp_formats():
    """Get supported Burp Suite export formats."""
    return {
        "formats": [
            {
                "format": "json",
                "name": "JSON (HTTP History)",
                "description": "Standard JSON export from Burp Suite Proxy HTTP History",
                "edition": "community_and_professional",
                "steps": [
                    "1. Go to Proxy > HTTP History tab",
                    "2. Select requests (Ctrl+A for all)",
                    "3. Click 'Export' button",
                    "4. Choose 'JSON' format",
                    "5. Save and upload here"
                ]
            }
        ],
        "note": "Community Edition users: The JSON export is available in all Burp Suite editions"
    }


# ============ INPUT HANDLERS ============

class URLsInputRequest(BaseModel):
    urls: list[str]
    project_id: str | None = None


@app.post("/api/input/urls")
async def process_urls(req: URLsInputRequest):
    """Process URLs for web vulnerability analysis."""
    import httpx
    from bs4 import BeautifulSoup

    results = []
    for url in req.urls[:10]:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
                response = await client.get(url)

                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a.get('href', '') for a in soup.find_all('a', href=True)][:20]
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        "action": form.get('action', ''),
                        "method": form.get('method', 'get').upper(),
                        "inputs": [{"name": inp.get('name', ''), "type": inp.get('type', 'text'), "id": inp.get('id', '')}
                                   for inp in form.find_all('input')[:10]]
                    }
                    forms.append(form_data)

                results.append({
                    "url": url,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "links_found": len(links),
                    "forms_found": len(forms),
                    "forms": forms[:5],
                    "technologies": detect_technologies(response.headers, response.text),
                })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return {
        "status": "ok",
        "results": results,
        "count": len(results),
    }


def detect_technologies(headers: dict, html: str) -> dict:
    """Simple technology detection from headers and HTML."""
    tech = {}
    server = headers.get("server", "").lower()
    if "nginx" in server:
        tech["web_server"] = "nginx"
    elif "apache" in server:
        tech["web_server"] = "apache"
    elif "iis" in server:
        tech["web_server"] = "IIS"

    if "x-powered-by" in headers:
        tech["backend"] = headers["x-powered-by"]

    if "wordpress" in html.lower():
        tech["cms"] = "WordPress"
    elif "drupal" in html.lower():
        tech["cms"] = "Drupal"
    elif "joomla" in html.lower():
        tech["cms"] = "Joomla"

    if "react" in html.lower() or "create-react-app" in html.lower():
        tech["frontend"] = "React"
    elif "vue" in html.lower() or "vue.js" in html.lower():
        tech["frontend"] = "Vue.js"
    elif "angular" in html.lower():
        tech["frontend"] = "Angular"

    return tech


class FolderScanRequest(BaseModel):
    folder_path: str
    project_id: str | None = None
    file_types: list[str] | None = None


@app.post("/api/input/folder")
async def scan_folder(req: FolderScanRequest):
    """Scan a folder for source code files."""
    import os

    supported_extensions = req.file_types or [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sql", ".cs", ".c", ".cpp", ".h", ".hpp"]

    if not os.path.exists(req.folder_path):
        return {"status": "error", "error": f"Folder not found: {req.folder_path}"}

    if not os.path.isdir(req.folder_path):
        return {"status": "error", "error": f"Path is not a directory: {req.folder_path}"}

    files_found = []
    total_size = 0

    for root, dirs, files in os.walk(req.folder_path):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.idea']]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in supported_extensions:
                filepath = os.path.join(root, filename)
                try:
                    size = os.path.getsize(filepath)
                    total_size += size
                    rel_path = os.path.relpath(filepath, req.folder_path)
                    files_found.append({
                        "path": rel_path,
                        "full_path": filepath,
                        "extension": ext,
                        "size_bytes": size,
                    })
                except Exception:
                    pass

    files_found.sort(key=lambda x: x["size_bytes"], reverse=True)

    return {
        "status": "ok",
        "folder": req.folder_path,
        "files_found": len(files_found),
        "total_size_bytes": total_size,
        "files": files_found[:50],
        "extensions": {ext: len([f for f in files_found if f["extension"] == ext]) for ext in supported_extensions},
    }


class PromptsInputRequest(BaseModel):
    prompt: str
    project_id: str | None = None
    context: dict | None = None


@app.post("/api/input/prompts")
async def process_prompt(req: PromptsInputRequest):
    """Process security testing prompts through AI."""
    if llm_router is None:
        return {"status": "error", "error": "LLM router not initialized. Please configure a provider in Settings."}

    from .providers import LLMMessage, MessageRole

    try:
        system_context = "You are SENTINEL-X, an autonomous security analysis assistant. Provide concise, actionable security guidance."

        messages = [
            LLMMessage(role=MessageRole.SYSTEM, content=system_context),
            LLMMessage(role=MessageRole.USER, content=req.prompt),
        ]

        if req.context:
            context_str = f"\nContext: {json.dumps(req.context)}"
            messages[1] = LLMMessage(role=MessageRole.USER, content=req.prompt + context_str)

        response = await llm_router.route_completion(messages, max_tokens=2000)

        return {
            "status": "ok",
            "response": response.content,
            "latency_ms": response.latency_ms,
        }
    except Exception as e:
        logger.error("prompt_processing_error", error=str(e))
        return {"status": "error", "error": str(e)}


@app.post("/api/input/code")
async def analyze_input_code(req: CodeAnalysisRequest):
    """Analyze code submitted through input sources."""
    project_id = req.file_path.split("/")[0] if "/" in req.file_path else "default"

    if project_id not in code_analyzers:
        code_analyzers[project_id] = CodeAnalyzer(project_id)

    analyzer = code_analyzers[project_id]
    patterns = analyzer.analyze_file(req.file_path, req.code, req.language)
    data_flows = analyzer.analyze_data_flow(req.file_path, req.code)
    auth_flows = [analyzer.analyze_auth_flow(req.file_path, req.code)]

    return {
        "status": "ok",
        "file_path": req.file_path,
        "patterns": [p.to_dict() for p in patterns],
        "data_flows": [f.to_dict() for f in data_flows],
        "summary": {
            "patterns_found": len(patterns),
            "critical": len([p for p in patterns if p.severity.value == "critical"]),
            "high": len([p for p in patterns if p.severity.value == "high"]),
            "data_flows": len(data_flows),
            "unsafe_flows": len([f for f in data_flows if not f.is_safe]),
        },
    }
