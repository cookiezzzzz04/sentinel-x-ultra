"""Fix all issues: normalize severity casing, remove duplicate endpoints, add /api/burp/upload, add target domain input to BugBountyPanel."""
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
server_path = os.path.join(script_dir, 'sentinel_x_ultra', 'server.py')
app_path = os.path.join(script_dir, 'frontend', 'src', 'App.tsx')
code_analyzer_path = os.path.join(script_dir, 'sentinel_x_ultra', 'analyzers', 'code_analyzer.py')

print(f'Files all exist: {os.path.exists(server_path) and os.path.exists(app_path) and os.path.exists(code_analyzer_path)}')

# ============ FILE 1: code_analyzer.py - Normalize severity casing ============
with open(code_analyzer_path, encoding='utf-8', errors='replace') as f:
    ca_content = f.read()

ca_changes = 0

old_severity = """class Severity(str, Enum):
    CRITICAL = \"critical\"
    HIGH = \"high\"
    MEDIUM = \"medium\"
    LOW = \"low\"
    INFORMATIONAL = \"informational\""""

new_severity = """class Severity(str, Enum):
    CRITICAL = \"CRITICAL\"
    HIGH = \"HIGH\"
    MEDIUM = \"MEDIUM\"
    LOW = \"LOW\"
    INFORMATIONAL = \"INFORMATIONAL\""""

if old_severity in ca_content:
    ca_content = ca_content.replace(old_severity, new_severity, 1)
    print('1. Severity enum normalized to UPPERCASE')
    ca_changes += 1
else:
    print('1. FAILED: Severity enum not found')

if ca_changes > 0:
    with open(code_analyzer_path, 'w', encoding='utf-8') as f:
        f.write(ca_content)

# ============ FILE 2: server.py ============
with open(server_path, encoding='utf-8', errors='replace') as f:
    sv_content = f.read()

sv_changes = 0

# Remove duplicate endpoint block starting with second URLsInputRequest
old_dup = """class URLsInputRequest(BaseModel):
    urls: list[str]
    project_id: str | None = None


@app.post(\"/api/input/folder\")
async def scan_folder(req: FolderScanRequest):
    \"\"\"Scan a folder for source code files.\"\"\"
    import os

    supported_extensions = req.file_types or [\".py\", \".js\", \".ts\", \".jsx\", \".tsx\", \".java\", \".go\", \".rb\", \".php\", \".sql\", \".cs\", \".c\", \".cpp\", \".h\", \".hpp\"]

    if not os.path.exists(req.folder_path):
        return {\"status\": \"error\", \"error\": f\"Folder not found: {req.folder_path}\"}

    if not os.path.isdir(req.folder_path):
        return {\"status\": \"error\", \"error\": f\"Path is not a directory: {req.folder_path}\"}

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
                        \"path\": rel_path,
                        \"full_path\": filepath,
                        \"extension\": ext,
                        \"size_bytes\": size,
                    })
                except Exception:
                    pass

    files_found.sort(key=lambda x: x[\"size_bytes\"], reverse=True)

    return {
        \"status\": \"ok\",
        \"folder\": req.folder_path,
        \"files_found\": len(files_found),
        \"total_size_bytes\": total_size,
        \"files\": files_found[:50],
        \"extensions\": {ext: len([f for f in files_found if f[\"extension\"] == ext]) for ext in supported_extensions},
    }


class PromptsInputRequest(BaseModel):
    prompt: str
    project_id: str | None = None
    context: dict | None = None


@app.post(\"/api/input/prompts\")
async def process_prompt(req: PromptsInputRequest):
    \"\"\"Process security testing prompts through AI.\"\"\"
    if llm_router is None:
        return {\"status\": \"error\", \"error\": \"LLM router not initialized. Please configure a provider in Settings.\"}

    from .providers import LLMMessage, MessageRole

    try:
        system_context = \"You are SENTINEL-X, an autonomous security analysis assistant. Provide concise, actionable security guidance.\"

        messages = [
            LLMMessage(role=MessageRole.SYSTEM, content=system_context),
            LLMMessage(role=MessageRole.USER, content=req.prompt),
        ]

        if req.context:
            context_str = f\"\\nContext: {json.dumps(req.context)}\"
            messages[1] = LLMMessage(role=MessageRole.USER, content=req.prompt + context_str)

        response = await llm_router.complete(messages, max_tokens=2000)

        return {
            \"status\": \"ok\",
            \"response\": response.content,
            \"latency_ms\": response.latency_ms,
        }
    except Exception as e:
        logger.error(\"prompt_processing_error\", error=str(e))
        return {\"status\": \"error\", \"error\": str(e)}


@app.post(\"/api/input/code\")
async def analyze_input_code(req: CodeAnalysisRequest):
    \"\"\"Analyze code submitted through input sources.\"\"\"
    project_id = req.file_path.split(\"/\")[0] if \"/\" in req.file_path else \"default\"

    if project_id not in code_analyzers:
        code_analyzers[project_id] = CodeAnalyzer(project_id)

    analyzer = code_analyzers[project_id]
    patterns = analyzer.analyze_file(req.file_path, req.code, req.language)
    data_flows = analyzer.analyze_data_flow(req.file_path, req.code)
    auth_flows = [analyzer.analyze_auth_flow(req.file_path, req.code)]

    return {
        \"status\": \"ok\","""

if old_dup in sv_content:
    new_replacement = """class BurpUploadRequest(BaseModel):
    burp_data: list | dict | None = None
    format: str = "json"


@app.post("/api/burp/upload")
async def upload_burp_export(req: BurpUploadRequest):
    \"\"\"Upload Burp Suite JSON export for analysis.\"\"\"
    try:
        burp_data = req.burp_data or []
        if isinstance(burp_data, dict):
            burp_data = [burp_data]

        findings = []
        total_requests = len(burp_data)
        api_endpoints = 0
        auth_headers_found = 0
        error_responses = 0

        for item in burp_data:
            url = item.get("url", "") if isinstance(item, dict) else ""
            method = item.get("method", "GET") if isinstance(item, dict) else ""
            status = item.get("status", item.get("responseCode", 0)) if isinstance(item, dict) else 0

            if "/api/" in url.lower() or "/rest/" in url.lower():
                api_endpoints += 1
                findings.append({"type": "api_endpoint", "url": url, "method": method})

            if isinstance(status, int) and status >= 400:
                error_responses += 1
                findings.append({"type": "error_response", "url": url, "method": method, "code": status})

            request_data = item.get("request", {}) if isinstance(item, dict) else {}
            if isinstance(request_data, dict):
                headers_str = str(request_data.get("headers", ""))
                if "authorization" in headers_str.lower() or "bearer" in headers_str.lower():
                    auth_headers_found += 1
                    findings.append({"type": "auth_header", "url": url, "method": method})

        return {
            "status": "ok",
            "summary": {
                "total_requests": total_requests,
                "api_endpoints": api_endpoints,
                "auth_endpoints": auth_headers_found,
                "error_responses": error_responses,
                "security_findings": len(findings),
            },
            "findings": findings[:50],
            "format": req.format,
        }
    except Exception as e:
        logger.error("burp_upload_error", error=str(e))
        return {"status": "error", "error": str(e)}"""

    sv_content = sv_content.replace(old_dup, new_replacement, 1)
    print('2. Removed duplicate endpoints, added /api/burp/upload')
    sv_changes += 1
else:
    print('2. FAILED: Duplicate endpoints not found')

# Update severity comparisons
sv_content = sv_content.replace('p.severity.value == "critical"', 'p.severity.value == "CRITICAL"')
sv_content = sv_content.replace('p.severity.value == "high"', 'p.severity.value == "HIGH"')
sv_content = sv_content.replace('p.severity.value == "medium"', 'p.severity.value == "MEDIUM"')
print('3. Updated severity comparisons to UPPERCASE')

if sv_changes > 0:
    with open(server_path, 'w', encoding='utf-8') as f:
        f.write(sv_content)

# ============ FILE 3: App.tsx ============
with open(app_path, encoding='utf-8', errors='replace') as f:
    app_content = f.read()

app_changes = 0

# Add targetDomain state
old_state = """  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineResult, setPipelineResult] = useState<any>(null);
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<any>(null);
  const [webhookUrl, setWebhookUrl] = useState('');"""

new_state = """  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineResult, setPipelineResult] = useState<any>(null);
  const [targetDomain, setTargetDomain] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<any>(null);
  const [webhookUrl, setWebhookUrl] = useState('');"""

if old_state in app_content:
    app_content = app_content.replace(old_state, new_state, 1)
    print('4. Added targetDomain state')
    app_changes += 1
else:
    print('4. FAILED: State init not found')

# Update pipeline request body
old_body = """        body: JSON.stringify({ target_domain: 'example.com', in_scope: ['example.com'], project_id: projectId }),"""

new_body = """        body: JSON.stringify({ target_domain: targetDomain || 'example.com', in_scope: [targetDomain || 'example.com'], project_id: projectId }),"""

if old_body in app_content:
    app_content = app_content.replace(old_body, new_body, 1)
    print('5. Pipeline request uses targetDomain')
    app_changes += 1
else:
    print('5. FAILED: Pipeline body not found')

# Add target domain input to pipeline card
old_card = """          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Run Full Pipeline</h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '16px' }}>Run all 10 agents in sequence: URL Parser -> Policy Enforcer -> Scope Guardian -> Passive Intel -> Active Enum -> Vuln Scanner -> Validation Engine -> Exploitation -> Analysis -> Report Generation</p>
          <button onClick={runPipeline} disabled={pipelineRunning} style={{"""

new_card = """          <h3 style={{ fontSize: '16px', fontWeight: '600', marginBottom: '16px' }}>Run Full Pipeline</h3>
          <p style={{ fontSize: '12px', color: '#888', marginBottom: '12px' }}>Run all 10 agents in sequence: URL Parser -> Policy Enforcer -> Scope Guardian -> Passive Intel -> Active Enum -> Vuln Scanner -> Validation Engine -> Exploitation -> Analysis -> Report Generation</p>
          <div style={{ marginBottom: '12px' }}>
            <input type="text" value={targetDomain} onChange={e => setTargetDomain(e.target.value)} placeholder="Target domain (e.g. example.com)" style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #333', background: '#1a1a2e', color: '#fff', fontSize: '13px' }} />
          </div>
          <button onClick={runPipeline} disabled={pipelineRunning} style={{"""

if old_card in app_content:
    app_content = app_content.replace(old_card, new_card, 1)
    print('6. Added target domain input to pipeline card')
    app_changes += 1
else:
    print('6. FAILED: Pipeline card not found. Searching...')
    idx = app_content.find('Run all 10 agents in sequence')
    if idx >= 0:
        start = max(0, idx - 100)
        end = min(len(app_content), idx + 300)
        print(repr(app_content[start:end]).replace('\\n', '\\n'))

# Fix old hardcoded domain in AgentsPanel
old_agent = "{ scope: { domains: ['example.com'] } }"
new_agent = "{ scope: { domains: [targetDomain || 'example.com'] } }"

agent_count = app_content.count(old_agent)
if agent_count > 0:
    app_content = app_content.replace(old_agent, new_agent, agent_count)
    print(f'7. Updated {agent_count} hardcoded domain reference(s)')
    app_changes += 1

if app_changes > 0:
    with open(app_path, 'w', encoding='utf-8') as f:
        f.write(app_content)

print(f'\nDone. {ca_changes} severity, {sv_changes} server, {app_changes} frontend changes.')
