# ============ AGENT MODEL PERSISTENCE ============

class AgentMemoryRequest(BaseModel):
    agent_id: str
    model_preference: str | None = None
    learning: str | None = None


@app.post("/api/projects/{project_id}/agent-memory")
async def save_agent_memory(project_id: str, req: AgentMemoryRequest):
    """Save agent memory (model preference and learnings) for a project."""
    from .project_context import AgentMemory, ProjectContext

    context = ProjectContext(settings.storage.base_path / "context")

    existing = context.get_agent_memory(project_id, req.agent_id) or AgentMemory(agent_id=req.agent_id)

    if req.model_preference:
        existing.model_preference = req.model_preference

    if req.learning:
        existing.learnings.append({
            "learning": req.learning,
            "timestamp": datetime.utcnow().isoformat()
        })

    existing.last_run = datetime.utcnow().isoformat()

    context.save_agent_memory(project_id, req.agent_id, existing)

    return {"status": "ok", "message": f"Agent memory saved for {req.agent_id}"}


@app.get("/api/projects/{project_id}/agent-memory")
async def get_agent_memory(project_id: str, agent_id: str = None):
    """Get agent memory for a specific agent or all agents."""
    from .project_context import ProjectContext

    context = ProjectContext(settings.storage.base_path / "context")

    if agent_id:
        memory = context.get_agent_memory(project_id, agent_id)
        if memory:
            return memory.to_dict()
        return {"error": "Agent memory not found"}
    else:
        memories = context.get_all_agent_memories(project_id)
        return {"memories": [m.to_dict() for m in memories]}


@app.get("/api/owasp-knowledge")
async def get_owasp_knowledge():
    """Get OWASP Top 10 knowledge for agent system prompts."""
    from .project_context import get_owasp_top10_prompt
    return {"owasp_knowledge": get_owasp_top10_prompt()}


# ============ BUG BOUNTY PROGRAM INTEGRATION ============

class BugBountyProgramRequest(BaseModel):
    program_url: str
    platform: str = "hackerone"
    scope: Dict[str, Any] | None = None
    tech_stack: Dict[str, Any] | None = None
    test_accounts: List[Dict[str, str]] | None = None
    roles: Dict[str, List[str]] | None = None
    notes: str = ""


@app.post("/api/projects/{project_id}/bugbounty")
async def save_bug_bounty_program(project_id: str, req: BugBountyProgramRequest):
    """Save bug bounty program context for a project."""
    from .project_context import BugBountyProgram, ProjectContext

    context = ProjectContext(settings.storage.base_path / "context")

    program = BugBountyProgram(
        program_url=req.program_url,
        platform=req.platform,
        scope=req.scope or {"in_scope": [], "out_of_scope": [], "restrictions": []},
        tech_stack=req.tech_stack or {},
        test_accounts=req.test_accounts or [],
        roles=req.roles or {},
        notes=req.notes
    )

    context.save_bug_bounty_program(project_id, program)

    return {"status": "ok", "message": "Bug bounty program saved"}


@app.get("/api/projects/{project_id}/bugbounty")
async def get_bug_bounty_program(project_id: str):
    """Get bug bounty program context for a project."""
    from .project_context import ProjectContext, get_bug_bounty_context_prompt

    context = ProjectContext(settings.storage.base_path / "context")

    program = context.get_bug_bounty_program(project_id)
    if program:
        return {
            "program": program.to_dict(),
            "context_prompt": get_bug_bounty_context_prompt(program)
        }
    return {"error": "No bug bounty program found"}


@app.post("/api/bugbounty/fetch-scope")
async def fetch_bugbounty_scope(req: BugBountyProgramRequest):
    """Fetch bug bounty program scope from URL (HackerOne, Bugcrowd, etc)."""
    import httpx
    from bs4 import BeautifulSoup

    scope = {"in_scope": [], "out_of_scope": [], "restrictions": []}
    tech_stack = {}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if req.platform == "hackerone" and "hackerone.com" in req.program_url:
                # Fetch HackerOne program page
                response = await client.get(req.program_url, headers={"User-Agent": "SENTINEL-X/1.0"})

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract in-scope targets
                    in_scope_section = soup.find_all(['ul', 'div'], class_=lambda x: x and 'in-scope' in x.lower() if x else False)
                    for section in in_scope_section:
                        for item in section.find_all('li'):
                            target = item.get_text(strip=True)
                            if target and len(target) > 3:
                                scope["in_scope"].append(target)

                    # Extract tech stack
                    tech_keywords = ["React", "Node.js", "Python", "Java", "Go", "Ruby", "AWS", "Azure", "PostgreSQL", "MongoDB"]
                    page_text = soup.get_text()
                    for tech in tech_keywords:
                        if tech.lower() in page_text.lower():
                            tech_stack[tech] = "Found in program page"

                    # Extract restrictions
                    restrictions_section = soup.find_all(['ul', 'div'], class_=lambda x: x and 'restriction' in x.lower() if x else False)
                    for section in restrictions_section:
                        for item in section.find_all('li'):
                            restriction = item.get_text(strip=True)
                            if restriction:
                                scope["restrictions"].append(restriction)

    except Exception as e:
        return {"status": "partial", "scope": scope, "tech_stack": tech_stack, "error": str(e)}

    return {"status": "ok", "scope": scope, "tech_stack": tech_stack}


# ============ BURP SUITE PROXY (Community Edition) ============

class BurpProxyRequest(BaseModel):
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] | None = None
    body: str | None = None
    upstream_proxy: str = "http://localhost:8080"


@app.post("/api/burp/proxy-request")
async def burp_proxy_request(req: BurpProxyRequest):
    """Forward request through Burp Suite proxy for analysis."""
    from .burp_proxy import BurpProxyAnalyzer

    analyzer = BurpProxyAnalyzer(upstream_proxy=req.upstream_proxy)

    headers = req.headers or {}

    result = await analyzer.analyze_request(
        method=req.method,
        url=req.target_url,
        headers=headers,
        body=req.body
    )

    return {"status": "ok", "analysis": result}


@app.post("/api/burp/proxy-analyze")
async def burp_proxy_analyze(req: BurpProxyRequest):
    """Analyze a request/response pair through Burp Suite proxy."""
    import httpx

    from .burp_proxy import BurpProxyAnalyzer

    analyzer = BurpProxyAnalyzer(upstream_proxy=req.upstream_proxy)
    headers = req.headers or {}

    # Analyze request
    request_analysis = await analyzer.analyze_request(
        method=req.method,
        url=req.target_url,
        headers=headers,
        body=req.body
    )

    # Try to get response through proxy
    response_analysis = None
    try:
        async with httpx.AsyncClient(timeout=30.0, proxies=req.upstream_proxy) as client:
            response = await client.request(
                method=req.method,
                url=req.target_url,
                headers=headers,
                content=req.body
            )
            response_analysis = await analyzer.analyze_response(
                url=req.target_url,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text
            )
    except Exception as e:
        response_analysis = {"error": str(e)}

    return {
        "status": "ok",
        "request_analysis": request_analysis,
        "response_analysis": response_analysis,
        "summary": analyzer.get_summary()
    }


@app.get("/api/burp/proxy-summary")
async def get_burp_proxy_summary(upstream_proxy: str = "http://localhost:8080"):
    """Get summary of all proxied requests."""
    from .burp_proxy import BurpProxyAnalyzer

    analyzer = BurpProxyAnalyzer(upstream_proxy=upstream_proxy)
    return analyzer.get_summary()
