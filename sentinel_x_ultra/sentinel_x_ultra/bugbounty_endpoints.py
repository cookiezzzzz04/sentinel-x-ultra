# ============ BUG BOUNTY PROGRAM INTEGRATION ============

from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .project_context import ProjectContext, BugBountyProgram, AgentMemory, get_owasp_top10_prompt, get_bug_bounty_context_prompt

# Create router for bug bounty endpoints
router = APIRouter(prefix="/api", tags=["bugbounty"])

# Lazy initialization for project context
_globals = globals()
def _get_settings():
    from . import server as _server_module
    return _server_module.settings

def get_project_context():
    """Lazy initialization of project context"""
    settings = _get_settings()
    return ProjectContext(settings.storage.base_path / "context")

project_context = None

def _ensure_context():
    global project_context
    if project_context is None:
        settings = _get_settings()
        project_context = ProjectContext(settings.storage.base_path / "context")
    return project_context


class BugBountyProgramRequest(BaseModel):
    program_url: str
    platform: str = "hackerone"


class BugBountyProgramUpdate(BaseModel):
    scope: Dict[str, Any] = None
    tech_stack: Dict[str, Any] = None
    test_accounts: List[Dict[str, str]] = None
    roles: Dict[str, List[str]] = None
    findings: List[Dict[str, Any]] = None
    dismissed: List[Dict[str, str]] = None
    notes: str = None
    report_template: str = None


class AgentMemoryRequest(BaseModel):
    agent_id: str
    model_preference: str = None
    learning: str = None


@router.post("/projects/{project_id}/bugbounty")
async def save_bug_bounty_program(project_id: str, req: BugBountyProgramRequest):
    """Save bug bounty program from URL - parses scope and sets up context"""
    try:
        program_url = req.program_url
        
        # Create program with URL
        program = BugBountyProgram(
            program_url=program_url,
            platform=req.platform
        )
        
        # Get context and save program
        ctx = _ensure_context()
        success = ctx.save_bug_bounty_program(project_id, program)
        
        if success:
            return {
                "status": "ok",
                "message": "Bug bounty program saved",
                "program": program.to_dict()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save program")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/projects/{project_id}/bugbounty")
async def get_bug_bounty_program(project_id: str):
    """Get saved bug bounty program for a project"""
    ctx = _ensure_context()
    program = ctx.get_bug_bounty_program(project_id)
    if program:
        return {"status": "ok", "program": program.to_dict()}
    return {"status": "not_found", "program": None}


@router.put("/projects/{project_id}/bugbounty")
async def update_bug_bounty_program(project_id: str, req: BugBountyProgramUpdate):
    """Update bug bounty program details"""
    ctx = _ensure_context()
    program = ctx.get_bug_bounty_program(project_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    # Update fields
    if req.scope is not None:
        program.scope = req.scope
    if req.tech_stack is not None:
        program.tech_stack = req.tech_stack
    if req.test_accounts is not None:
        program.test_accounts = req.test_accounts
    if req.roles is not None:
        program.roles = req.roles
    if req.findings is not None:
        program.findings = req.findings
    if req.dismissed is not None:
        program.dismissed = req.dismissed
    if req.notes is not None:
        program.notes = req.notes
    if req.report_template is not None:
        program.report_template = req.report_template
    
    ctx = _ensure_context()
    success = ctx.save_bug_bounty_program(project_id, program)
    
    if success:
        return {"status": "ok", "program": program.to_dict()}
    raise HTTPException(status_code=500, detail="Failed to update program")


@router.post("/projects/{project_id}/agent-memory")
async def save_agent_memory(project_id: str, req: AgentMemoryRequest):
    """Save agent memory - model used and learnings"""
    ctx = _ensure_context()
    memory = ctx.get_agent_memory(project_id, req.agent_id) or AgentMemory(agent_id=req.agent_id)
    
    if req.model_preference:
        memory.model_preference = req.model_preference
    if req.learning:
        memory.learnings.append({
            "learning": req.learning,
            "timestamp": datetime.utcnow().isoformat()
        })
    memory.last_run = datetime.utcnow().isoformat()
    
    ctx = _ensure_context()
    success = ctx.save_agent_memory(project_id, req.agent_id, memory)
    
    if success:
        return {"status": "ok", "memory": memory.to_dict()}
    raise HTTPException(status_code=500, detail="Failed to save agent memory")


@router.get("/projects/{project_id}/agent-memory")
async def get_agent_memory(project_id: str, agent_id: str = None):
    """Get agent memory - optionally for specific agent"""
    ctx = _ensure_context()
    if agent_id:
        memory = ctx.get_agent_memory(project_id, agent_id)
        if memory:
            return {"status": "ok", "memory": memory.to_dict()}
        return {"status": "not_found", "memory": None}
    else:
        memories = ctx.get_all_agent_memories(project_id)
        return {"status": "ok", "memories": [m.to_dict() for m in memories]}


@router.get("/owasp-top10")
async def get_owasp_top10():
    """Get OWASP Top 10 knowledge for agents - embedded in every agent's thinking"""
    return {
        "status": "ok",
        "owasp_prompt": get_owasp_top10_prompt(),
        "categories": [
            {"id": "A01", "name": "Broken Access Control", "severity": "critical"},
            {"id": "A02", "name": "Cryptographic Failures", "severity": "high"},
            {"id": "A03", "name": "Injection", "severity": "critical"},
            {"id": "A04", "name": "Insecure Design", "severity": "high"},
            {"id": "A05", "name": "Security Misconfiguration", "severity": "high"},
            {"id": "A06", "name": "Vulnerable Components", "severity": "high"},
            {"id": "A07", "name": "Authentication Failures", "severity": "high"},
            {"id": "A08", "name": "Software Integrity Failures", "severity": "medium"},
            {"id": "A09", "name": "Security Logging Failures", "severity": "medium"},
            {"id": "A10", "name": "Server-Side Request Forgery", "severity": "critical"},
        ]
    }


# ============ AGENT SYSTEM PROMPT ENHANCEMENT ============

def get_agent_system_prompt(agent_type: str, project_id: str = None) -> str:
    """Get enhanced system prompt for agent with OWASP and bug bounty context"""
    prompt = f"""You are a security testing agent specialized in {agent_type}.

## Your Core Knowledge - ALWAYS ACTIVE:

{get_owasp_top10_prompt()}

## Your Role:
- Perform thorough security testing
- Document findings with PoC and business impact
- Always consider OWASP Top 10 vulnerabilities
- Follow ethical testing guidelines
"""
    
    # Add bug bounty context if available
    if project_id:
        ctx = _ensure_context()
        program = ctx.get_bug_bounty_program(project_id)
        if program:
            prompt += f"\n\n{get_bug_bounty_context_prompt(program)}"
        
        # Add agent memory
        memory = ctx.get_agent_memory(project_id, agent_type)
        if memory and memory.learnings:
            prompt += "\n\n## Previous Learnings (Don't repeat mistakes):"
            for learning in memory.learnings[-5:]:  # Last 5 learnings
                if isinstance(learning, dict):
                    prompt += f"\n• {learning.get('learning', '')}"
                else:
                    prompt += f"\n• {learning}"
    
    return prompt