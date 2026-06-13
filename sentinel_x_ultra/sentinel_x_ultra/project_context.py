"""
Project Context Storage - For bug bounty programs, agent learnings, and OWASP knowledge
This file stores persistent context that agents can remember across sessions.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class BugBountyProgram:
    """Stores bug bounty program scope and context"""

    def __init__(
        self,
        program_url: str,
        platform: str = "hackerone",
        scope: dict[str, Any] = None,
        tech_stack: dict[str, Any] = None,
        test_accounts: list[dict[str, str]] = None,
        roles: dict[str, list[str]] = None,
        findings: list[dict[str, Any]] = None,
        dismissed: list[dict[str, str]] = None,
        notes: str = "",
        report_template: str = "",
        created_at: str = None
    ):
        self.program_url = program_url
        self.platform = platform
        self.scope = scope or {"in_scope": [], "out_of_scope": [], "restrictions": []}
        self.tech_stack = tech_stack or {}
        self.test_accounts = test_accounts or []
        self.roles = roles or {}
        self.findings = findings or []
        self.dismissed = dismissed or []
        self.notes = notes
        self.report_template = report_template
        self.created_at = created_at or datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "program_url": self.program_url,
            "platform": self.platform,
            "scope": self.scope,
            "tech_stack": self.tech_stack,
            "test_accounts": self.test_accounts,
            "roles": self.roles,
            "findings": self.findings,
            "dismissed": self.dismissed,
            "notes": self.notes,
            "report_template": self.report_template,
            "created_at": self.created_at
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BugBountyProgram":
        return cls(**data)


class AgentMemory:
    """Stores agent learnings and model preferences per project"""

    def __init__(
        self,
        agent_id: str,
        model_preference: str = "",
        learnings: list[str] = None,
        last_run: str = None,
        total_runs: int = 0
    ):
        self.agent_id = agent_id
        self.model_preference = model_preference
        self.learnings = learnings or []
        self.last_run = last_run
        self.total_runs = total_runs

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "model_preference": self.model_preference,
            "learnings": self.learnings,
            "last_run": self.last_run,
            "total_runs": self.total_runs
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentMemory":
        return cls(**data)


class ProjectContext:
    """Manages project context storage including bug bounty programs and agent memory"""

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _get_project_dir(self, project_id: str) -> Path:
        project_dir = self.storage_path / hashlib.md5(project_id.encode()).hexdigest()[:8]
        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir

    def save_bug_bounty_program(self, project_id: str, program: BugBountyProgram) -> bool:
        """Save bug bounty program context for a project"""
        try:
            project_dir = self._get_project_dir(project_id)
            file_path = project_dir / "bugbounty_program.json"
            with open(file_path, 'w') as f:
                json.dump(program.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving bug bounty program: {e}")
            return False

    def get_bug_bounty_program(self, project_id: str) -> BugBountyProgram | None:
        """Load bug bounty program context for a project"""
        try:
            project_dir = self._get_project_dir(project_id)
            file_path = project_dir / "bugbounty_program.json"
            if file_path.exists():
                with open(file_path) as f:
                    return BugBountyProgram.from_dict(json.load(f))
            return None
        except Exception as e:
            print(f"Error loading bug bounty program: {e}")
            return None

    def save_agent_memory(self, project_id: str, agent_id: str, memory: AgentMemory) -> bool:
        """Save agent memory (model preference, learnings) for a project"""
        try:
            project_dir = self._get_project_dir(project_id)
            agent_file = project_dir / f"agent_{agent_id}.json"
            with open(agent_file, 'w') as f:
                json.dump(memory.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving agent memory: {e}")
            return False

    def get_agent_memory(self, project_id: str, agent_id: str) -> AgentMemory | None:
        """Load agent memory for a specific agent in a project"""
        try:
            project_dir = self._get_project_dir(project_id)
            agent_file = project_dir / f"agent_{agent_id}.json"
            if agent_file.exists():
                with open(agent_file) as f:
                    return AgentMemory.from_dict(json.load(f))
            return None
        except Exception as e:
            print(f"Error loading agent memory: {e}")
            return None

    def get_all_agent_memories(self, project_id: str) -> list[AgentMemory]:
        """Get all agent memories for a project"""
        memories = []
        try:
            project_dir = self._get_project_dir(project_id)
            for file in project_dir.glob("agent_*.json"):
                with open(file) as f:
                    memories.append(AgentMemory.from_dict(json.load(f)))
        except Exception as e:
            print(f"Error loading agent memories: {e}")
        return memories

    def add_learning(self, project_id: str, agent_id: str, learning: str) -> bool:
        """Add a learning to an agent's memory"""
        memory = self.get_agent_memory(project_id, agent_id) or AgentMemory(agent_id=agent_id)
        memory.learnings.append({
            "learning": learning,
            "timestamp": datetime.utcnow().isoformat()
        })
        return self.save_agent_memory(project_id, agent_id, memory)

    def update_model_usage(self, project_id: str, agent_id: str, model: str) -> bool:
        """Update the model used for an agent"""
        memory = self.get_agent_memory(project_id, agent_id) or AgentMemory(agent_id=agent_id)
        memory.model_preference = model
        memory.last_run = datetime.utcnow().isoformat()
        memory.total_runs = memory.total_runs + 1
        return self.save_agent_memory(project_id, agent_id, memory)


def get_owasp_top10_prompt() -> str:
    """Returns OWASP Top 10 knowledge as a prompt string for agents - embedded in every agent's thinking"""
    return """
## OWASP Top 10:2021 - ALWAYS IN AGENT'S MIND

When analyzing, testing, or reviewing ALWAYS consider these vulnerabilities:

### A01: Broken Access Control (Most Critical!)
- Direct object reference (IDOR) - change /users/123 to /users/124
- Privilege escalation - can regular user access admin functions?
- Missing authorization checks on APIs
- CWE-639: Authorization Bypass Through User-Controlled Key

### A02: Cryptographic Failures
- Sensitive data exposure (PII, credentials, credit cards)
- Data in transit not encrypted (HTTP vs HTTPS)
- Weak algorithms (MD5, SHA1, DES)
- No encryption at rest for sensitive data

### A03: Injection
- SQL Injection: ' OR '1'='1, 1' UNION SELECT NULL--
- XSS: <script>alert(1)</script>, <img src=x onerror=alert(1)>
- Command Injection: ; ls, && whoami, | cat /etc/passwd
- LDAP/XPath/ORM Injection
- Always check: user input -> unvalidated -> interpreter

### A04: Insecure Design
- No threat modeling done
- Missing rate limiting
- Missing resource allocation limits
- Business logic flaws (race conditions, etc.)

### A05: Security Misconfiguration
- Default credentials active
- Debug mode enabled in production
- Error messages reveal stack traces
- Missing security headers (CSP, X-Frame-Options, etc.)
- Unnecessary features enabled

### A06: Vulnerable Components
- Outdated dependencies with known CVEs
- Not scanning for vulnerabilities
- Using components with unpatched flaws

### A07: Authentication Failures
- Weak password policies
- No multi-factor authentication (MFA)
- Credential stuffing attacks possible
- Session fixation / session prediction
- Exposing session IDs in URLs

### A08: Software Integrity Failures
- Deserializing untrusted data
- Relying on untrusted CDNs
- CI/CD pipeline not validated
- Auto-update without integrity verification

### A09: Security Logging Failures
- No logging of security events
- Errors not logged or logged to wrong place
- No alerting for attacks in progress
- Cannot reconstruct events after breach

### A10: Server-Side Request Forgery (SSRF)
- Fetching URLs without validation
- Accessing internal services (169.254.169.254 cloud metadata)
- file://, gopher://, dict:// protocol abuse
- Can bypass firewall restrictions

## ALWAYS TEST FOR:
1. Can I access resources I'm not authorized for?
2. Is user input properly validated/sanitized?
3. Is sensitive data properly encrypted?
4. Are there security misconfigurations?
5. Are dependencies up to date?
"""


def get_bug_bounty_context_prompt(program: BugBountyProgram) -> str:
    """Generate a prompt with bug bounty program context"""
    if not program:
        return ""

    prompt_parts = [f"""
## Bug Bounty Program Context - ALWAYS FOLLOW THIS SCOPE

### Program Platform: {program.platform.upper()}
### Program URL: {program.program_url}
"""]

    if program.scope:
        if program.scope.get("in_scope"):
            prompt_parts.append("\n**🎯 IN-SCOPE TARGETS:**")
            for target in program.scope["in_scope"]:
                prompt_parts.append(f"  ✓ {target}")

        if program.scope.get("out_of_scope"):
            prompt_parts.append("\n**🚫 OUT-OF-SCOPE:**")
            for target in program.scope["out_of_scope"]:
                prompt_parts.append(f"  ✗ {target}")

        if program.scope.get("restrictions"):
            prompt_parts.append("\n**⚠️ RESTRICTIONS:**")
            for restriction in program.scope["restrictions"]:
                prompt_parts.append(f"  ! {restriction}")

    if program.tech_stack:
        prompt_parts.append("\n**🛠️ TECH STACK:**")
        for tech, desc in program.tech_stack.items():
            prompt_parts.append(f"  • {tech}: {desc}")

    if program.roles:
        prompt_parts.append("\n**👥 USER ROLES:**")
        for role, permissions in program.roles.items():
            prompt_parts.append(f"  • {role}: {', '.join(permissions)}")

    if program.test_accounts:
        prompt_parts.append("\n**🔑 TEST ACCOUNTS:**")
        for account in program.test_accounts:
            name = account.get('name', 'Unknown')
            desc = account.get('description', 'No description')
            prompt_parts.append(f"  • {name}: {desc}")

    if program.findings:
        prompt_parts.append("\n**📊 CURRENT FINDINGS:**")
        for finding in program.findings:
            status = finding.get("status", "unknown")
            confidence = finding.get("confidence", 0)
            prompt_parts.append(f"  → [{status.upper()}] {finding.get('title', 'Untitled')} (Confidence: {confidence}%)")
            prompt_parts.append(f"    Impact: {finding.get('potential_impact', 'Not specified')}")
            prompt_parts.append(f"    Next: {finding.get('next_steps', 'Not specified')}")

    if program.dismissed:
        prompt_parts.append("\n**❌ DISMISSED (Won't Re-test):**")
        for dismissed in program.dismissed:
            prompt_parts.append(f"  • {dismissed.get('target', 'Unknown')}: {dismissed.get('reason', 'No reason')}")

    if program.notes:
        prompt_parts.append(f"\n**📝 PROJECT NOTES:**\n{program.notes}")

    prompt_parts.append("""
### 🔒 TESTING RULES:
1. ONLY test in-scope targets
2. Respect restrictions (no >5 req/s, no social engineering)
3. Don't touch real user data
4. Document PoC with business impact
5. Reference similar public reports for severity
""")

    return "\n".join(prompt_parts)
