"""Phase 3 Agents - Autonomous security analysis agents."""

from __future__ import annotations

import importlib
import importlib.util
import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any

import structlog

# Use explicit module loading to avoid circular imports caused by having
# both agents.py (file) and agents/ (directory) at the same package level

def _load_module_by_path(module_name: str, file_path: str):
    """Load a module directly from a file path, bypassing normal import resolution."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    return None

def _get_agents_module():
    """Lazily load the base agents module (agents.py file)."""
    module_name = 'sentinel_x_ultra.agents._base'
    if module_name not in sys.modules:
        init_dir = os.path.dirname(__file__)
        agents_py_path = os.path.join(os.path.dirname(init_dir), 'agents.py')
        _load_module_by_path(module_name, agents_py_path)
    return sys.modules[module_name]

def _get_providers_module():
    """Lazily load the providers module."""
    module_name = 'sentinel_x_ultra.agents._providers'
    if module_name not in sys.modules:
        init_dir = os.path.dirname(__file__)
        providers_py_path = os.path.join(os.path.dirname(init_dir), 'providers.py')
        _load_module_by_path(module_name, providers_py_path)
    return sys.modules[module_name]

def _get_models_module():
    """Lazily load the models module."""
    module_name = 'sentinel_x_ultra.agents._models'
    if module_name not in sys.modules:
        init_dir = os.path.dirname(__file__)
        models_py_path = os.path.join(os.path.dirname(init_dir), 'models.py')
        _load_module_by_path(module_name, models_py_path)
    return sys.modules[module_name]

# Pre-load modules at module initialization to ensure classes are available
# This happens once when this module is first imported
_agents_mod = _get_agents_module()
_providers_mod = _get_providers_module()
_models_mod = _get_models_module()

# Now get the actual class references
BaseAgent = _agents_mod.BaseAgent
AgentType = _agents_mod.AgentType
TaskPayload = _agents_mod.TaskPayload
MessageBus = _agents_mod.MessageBus
MessageType = _agents_mod.MessageType
AgentMessage = _agents_mod.AgentMessage

MultiProviderRouter = _providers_mod.MultiProviderRouter
LLMMessage = _providers_mod.LLMMessage
MessageRole = _providers_mod.MessageRole

Finding = _models_mod.Finding
Evidence = _models_mod.Evidence
AttackScenario = _models_mod.AttackScenario
Severity = _models_mod.Severity
Confidence = _models_mod.Confidence
FindingStatus = _models_mod.FindingStatus

logger = structlog.get_logger()


# ============ Base Phase 3 Agent ============

class Phase3Agent(BaseAgent):
    """Base class for Phase 3 specialized agents."""

    def __init__(
        self,
        agent_type: AgentType,
        message_bus: MessageBus,
        llm_router: MultiProviderRouter,
        project_id: str,
    ):
        super().__init__(agent_type, message_bus, llm_router)
        self.project_id = project_id
        self.findings: list[Finding] = []

    async def create_finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        evidence_data: dict[str, Any],
        remediation: str = "",
        cwe_ids: list[str] | None = None,
    ) -> Finding:
        """Create and track a new finding."""
        finding = Finding(
            id=str(uuid.uuid4()),
            title=title,
            severity=severity,
            confidence=confidence,
            affected_components=[self.project_id],
            description=description,
            evidence=[Evidence(
                source=f"{self.agent_type.value}_agent",
                description=f"Evidence from {self.agent_type.value} analysis",
                data=evidence_data,
            )],
            remediation=remediation,
            source_agent=self.agent_type.value,
            status=FindingStatus.PENDING,
            cwe_ids=cwe_ids or [],
            created_at=datetime.utcnow().isoformat(),
        )
        self.findings.append(finding)
        return finding

    async def broadcast_finding(self, finding: Finding):
        """Broadcast a finding to other agents."""
        await self.broadcast_event(
            event_type="new_finding",
            payload={
                "finding": finding.to_dict(),
                "source": self.agent_type.value,
            },
        )


# ============ Reconnaissance Agent ============

class ReconAgent(Phase3Agent):
    """Reconnaissance agent for target discovery and information gathering."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str):
        super().__init__(AgentType.RECON, message_bus, llm_router, project_id)

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute reconnaissance task."""
        action = task.input_data.get("action", "discover")

        if action == "discover":
            return await self.discover_targets(task.input_data)
        elif action == "scan":
            return await self.scan_target(task.input_data)
        elif action == "osint":
            return await self.perform_osint(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def discover_targets(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Discover potential targets from scope."""
        scope = input_data.get("scope", {})
        targets = []

        # Extract domains from scope
        domains = scope.get("domains", [])
        ip_ranges = scope.get("ip_ranges", [])
        urls = scope.get("urls", [])

        # Discover subdomains using common patterns
        discovered = []
        for domain in domains:
            # Add the main domain
            discovered.append({"type": "domain", "value": domain, "source": "scope"})

            # Generate common subdomains
            common_subdomains = [
                "www", "api", "app", "admin", "dev", "staging",
                "test", "beta", "mobile", "cdn", "assets",
                "mail", "smtp", "ftp", "ssh", "vpn",
            ]
            for sub in common_subdomains:
                discovered.append({
                    "type": "subdomain",
                    "value": f"{sub}.{domain}",
                    "source": "dns_brute_force",
                })

        # Parse URLs for endpoints
        endpoints = []
        for url in urls:
            parsed = self._parse_url(url)
            if parsed:
                endpoints.append(parsed)

        return {
            "status": "completed",
            "targets": discovered,
            "endpoints": endpoints,
            "summary": {
                "domains_found": len(discovered),
                "endpoints_found": len(endpoints),
            },
        }

    async def scan_target(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Scan a specific target for open ports and services."""
        target = input_data.get("target", "")
        scan_type = input_data.get("scan_type", "quick")

        results = {
            "target": target,
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
        }
        # Auto-use tool integration for enriched findings
        try:
            from ..agent_tool_integration import get_agent_tool_integration
            integration = get_agent_tool_integration()
            tool_report = await integration.scan_with_context("recon", target)
            results["tool_integration"] = tool_report.to_dict() if hasattr(tool_report, "to_dict") else {}
            results["tools_executed"] = len(tool_report.tools_executed) if hasattr(tool_report, "tools_executed") else 0
            results["tool_findings"] = tool_report.total_findings if hasattr(tool_report, "total_findings") else 0
        except Exception:
            pass

        # Common high-risk ports to check
        high_risk_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }

        # Simulate port scan results (in production, integrate with actual scanner)
        if scan_type == "quick":
            # Only check most common ports
            common_ports = [22, 80, 443, 8080]
            for port in common_ports:
                results["open_ports"].append(port)
                results["services"].append({
                    "port": port,
                    "service": high_risk_ports.get(port, "Unknown"),
                    "version": "unknown",
                })
        else:
            # Full scan of high-risk ports
            for port, service in high_risk_ports.items():
                results["open_ports"].append(port)
                results["services"].append({
                    "port": port,
                    "service": service,
                    "version": "unknown",
                })

        # Check for potential vulnerabilities based on open services
        for service in results["services"]:
            if service["service"] == "HTTP" or service["service"] == "HTTPS":
                # Could check for common web vulnerabilities
                pass

        # Create findings for interesting discoveries
        if results["open_ports"]:
            await self.create_finding(
                title=f"Open ports detected on {target}",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=f"Target has {len(results['open_ports'])} open ports: {results['open_ports']}",
                evidence_data={"ports": results["open_ports"], "services": results["services"]},
                remediation="Review open ports and ensure only necessary services are exposed",
            )

        return results

    async def perform_osint(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Perform OSINT (Open Source Intelligence) gather."""
        target = input_data.get("target", "")
        osint_type = input_data.get("type", "all")

        results = {
            "target": target,
            "leaked_creds": [],
            "leaked_db": [],
            "subdomain_takeovers": [],
            "info_gathered": {},
        }

        # Simulate OSINT findings (in production, use actual OSINT tools/APIs)
        info = {
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "nameservers": [],
            "emails": [],
            "related_domains": [],
        }

        # Create a finding if we found sensitive info
        if info.get("leaked_creds"):
            await self.create_finding(
                title=f"Potential credential leak for {target}",
                severity=Severity.CRITICAL,
                confidence=Confidence.LOW,
                description="Found potential leaked credentials through OSINT",
                evidence_data={"creds": info.get("leaked_creds")},
                remediation="Immediately rotate any potentially exposed credentials",
                cwe_ids=["CWE-312", "CWE-200"],
            )

        return results

    def _parse_url(self, url: str) -> dict[str, Any] | None:
        """Parse URL to extract components."""
        pattern = r'^(https?)://([^/:]+)(?::(\\d+))?(/.*)?$'
        match = re.match(pattern, url)
        if match:
            return {
                "scheme": match.group(1),
                "host": match.group(2),
                "port": match.group(3),
                "path": match.group(4) or "/",
            }
        return None


# ============ Code Review Agent ============

class CodeReviewAgent(Phase3Agent):
    """Code review agent using existing CodeAnalyzer."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str, code_analyzer: Any):
        super().__init__(AgentType.CODE_REVIEW, message_bus, llm_router, project_id)
        self.code_analyzer = code_analyzer

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute code review task."""
        action = task.input_data.get("action", "review")

        if action == "review":
            return await self.review_code(task.input_data)
        elif action == "deep_scan":
            return await self.deep_scan(task.input_data)
        elif action == "auth_review":
            return await self.review_auth_flow(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def review_code(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Review code for security issues."""
        code = input_data.get("code", "")
        file_path = input_data.get("file_path", "unknown")
        language = input_data.get("language")

        if not code:
            return {"status": "error", "message": "No code provided"}

        # Use the existing CodeAnalyzer
        patterns = self.code_analyzer.analyze_file(file_path, code, language)
        data_flows = self.code_analyzer.analyze_data_flow(file_path, code)

        # Create findings for critical issues
        critical_patterns = [p for p in patterns if p.severity.value == "critical"]
        for pattern in critical_patterns:
            await self.create_finding(
                title=f"Critical: {pattern.name}",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH if pattern.confidence == "high" else Confidence.MEDIUM,
                description=pattern.description,
                evidence_data={
                    "file": pattern.file_path,
                    "line": pattern.line_start,
                    "code_snippet": pattern.code_snippet,
                    "cwe": pattern.cwe.value if hasattr(pattern.cwe, 'value') else str(pattern.cwe),
                },
                remediation=f"Fix the {pattern.name.lower()} vulnerability at {file_path}:{pattern.line_start}",
                cwe_ids=[pattern.cwe.value if hasattr(pattern.cwe, 'value') else str(pattern.cwe)],
            )

        # Check for unsafe data flows
        unsafe_flows = [f for f in data_flows if not f.is_safe]
        for flow in unsafe_flows:
            await self.create_finding(
                title="Unsafe data flow detected",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=f"Tainted data flows from {flow.source.node_type} to {flow.sink.node_type} without sanitization",
                evidence_data={
                    "source": flow.source.expression,
                    "sink": flow.sink.expression,
                    "file": file_path,
                },
                remediation="Add input sanitization before using user-controlled data in sensitive operations",
                cwe_ids=["CWE-79", "CWE-89"],  # XSS and SQL Injection
            )

        return {
            "status": "completed",
            "patterns_found": len(patterns),
            "critical": len(critical_patterns),
            "high": len([p for p in patterns if p.severity.value == "high"]),
            "data_flows": len(data_flows),
            "unsafe_flows": len(unsafe_flows),
            "findings_created": len(self.findings),
        }

    async def deep_scan(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Perform deep security scan with LLM assistance."""
        files = input_data.get("files", [])  # List of {path, content}

        results = {
            "files_scanned": len(files),
            "total_issues": 0,
            "findings": [],
        }

        for file_data in files:
            path = file_data.get("path", "unknown")
            content = file_data.get("content", "")

            # Run standard review
            review_result = await self.review_code({
                "code": content,
                "file_path": path,
                "language": file_data.get("language"),
            })
            results["total_issues"] += review_result.get("critical", 0) + review_result.get("high", 0)

        # Use LLM for additional deep analysis on critical files
        if self.findings:
            critical_files = [f.to_dict() for f in self.findings if f.severity == Severity.CRITICAL]
            if critical_files:
                llm_analysis = await self._analyze_with_llm(critical_files)
                results["llm_insights"] = llm_analysis

        return results

    async def review_auth_flow(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Review authentication and authorization flows."""
        code = input_data.get("code", "")
        file_path = input_data.get("file_path", "unknown")

        auth_flow = self.code_analyzer.analyze_auth_flow(file_path, code)

        issues = auth_flow.issues
        if issues:
            await self.create_finding(
                title="Authentication/Authorization issues detected",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=f"Found {len(issues)} auth flow issues: {'; '.join(issues)}",
                evidence_data={"issues": issues, "steps": len(auth_flow.steps)},
                remediation="Review authentication implementation and ensure proper authorization checks",
                cwe_ids=["CWE-287", "CWE-862"],
            )

        return {
            "status": "completed",
            "is_secure": auth_flow.is_secure,
            "issues_found": len(issues),
            "recommendations": auth_flow.recommendations,
        }

    async def _analyze_with_llm(self, critical_findings: list[dict]) -> dict[str, Any]:
        """Use LLM to provide additional analysis on critical findings."""
        if not self.llm_router:
            return {"error": "No LLM router configured"}

        prompt = f"""Analyze these security findings and provide additional context:
{critical_findings}

For each finding, identify:
1. Potential false positive risks
2. Exploitation complexity
3. Business impact
4. Recommended immediate actions
"""

        messages = [LLMMessage(role=MessageRole.USER, content=prompt)]
        try:
            response = await self.llm_router.complete(messages, task_type="reasoning")
            return {"analysis": response.content, "model": response.model}
        except Exception as e:
            logger.error("llm_analysis_failed", error=str(e))
            return {"error": str(e)}


# ============ Threat Modeling Agent ============

class ThreatModelingAgent(Phase3Agent):
    """Threat modeling agent using KnowledgeGraph for attack path analysis."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str, knowledge_graph: Any):
        super().__init__(AgentType.THREAT_MODELING, message_bus, llm_router, project_id)
        self.knowledge_graph = knowledge_graph

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute threat modeling task."""
        action = task.input_data.get("action", "model")

        if action == "model":
            return await self.model_threats(task.input_data)
        elif action == "attack_paths":
            return await self.analyze_attack_paths(task.input_data)
        elif action == "impact":
            return await self.assess_impact(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def model_threats(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Create threat model from architecture data."""
        architecture = input_data.get("architecture", {})
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        trust_boundaries = architecture.get("trust_boundaries", [])

        threats = []

        # Analyze each component
        for component in components:
            component_threats = self._identify_component_threats(component)
            threats.extend(component_threats)

        # Analyze data flows
        for flow in data_flows:
            flow_threats = self._analyze_data_flow_threats(flow)
            threats.extend(flow_threats)

        # Create findings for high-risk threats
        for threat in threats:
            if threat["risk"] in ["critical", "high"]:
                await self.create_finding(
                    title=f"Threat: {threat['name']}",
                    severity=Severity.HIGH if threat["risk"] == "high" else Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description=threat["description"],
                    evidence_data={"threat": threat},
                    remediation=threat.get("mitigation", "Implement appropriate security controls"),
                    cwe_ids=threat.get("cwe_ids", []),
                )

        return {
            "status": "completed",
            "threats_identified": len(threats),
            "critical_threats": len([t for t in threats if t["risk"] == "critical"]),
            "threat_model": threats,
        }

    async def analyze_attack_paths(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Discover and analyze attack paths using the knowledge graph."""
        entry_points = input_data.get("entry_points")
        targets = input_data.get("targets")
        max_depth = input_data.get("max_depth", 5)

        # Use the knowledge graph to discover attack paths
        attack_paths = self.knowledge_graph.discover_attack_paths(
            entry_points=entry_points,
            targets=targets,
            max_depth=max_depth,
        )

        # Create findings for critical attack paths
        for path in attack_paths:
            if path.risk_level.value in ["critical", "high"]:
                await self.create_finding(
                    title=f"Attack path: {path.name}",
                    severity=Severity.CRITICAL if path.risk_level.value == "critical" else Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"Discovered {len(path.attack_steps)} step attack path with CVSS {path.cvss_score}",
                    evidence_data={
                        "steps": path.attack_steps,
                        "cvss": path.cvss_score,
                        "prerequisites": path.prerequisites,
                    },
                    remediation=f"Implement defense-in-depth: {path.attack_steps[0] if path.attack_steps else 'Review security controls'}",
                    cwe_ids=["CWE-693"],  # Protection Mechanism Failure
                )

        return {
            "status": "completed",
            "attack_paths_found": len(attack_paths),
            "critical_paths": len([p for p in attack_paths if p.risk_level.value == "critical"]),
            "paths": [p.to_dict() for p in attack_paths],
        }

    async def assess_impact(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Assess potential business impact of threats."""
        threat_id = input_data.get("threat_id", "")
        asset_value = input_data.get("asset_value", "medium")

        impact_levels = {
            "critical": {
                "description": "Catastrophic impact on business operations",
                "examples": ["Data breach exposing customer PII", "Ransomware encrypting critical systems"],
            },
            "high": {
                "description": "Significant impact on business operations",
                "examples": ["Service disruption affecting revenue", "Internal data exposure"],
            },
            "medium": {
                "description": "Moderate impact, manageable",
                "examples": ["Temporary service degradation", "Non-sensitive data exposure"],
            },
            "low": {
                "description": "Minimal impact",
                "examples": ["Minor information disclosure", "Temporary inconvenience"],
            },
        }

        return {
            "status": "completed",
            "threat_id": threat_id,
            "asset_value": asset_value,
            "impact_assessment": impact_levels.get(asset_value, impact_levels["medium"]),
        }

    def _identify_component_threats(self, component: dict[str, Any]) -> list[dict[str, Any]]:
        """Identify threats for a specific component."""
        threats = []
        component_type = component.get("type", "").lower()
        interfaces = component.get("interfaces", [])

        # Map component types to common threats
        threat_mappings = {
            "api": [
                {"name": "API Injection", "risk": "high", "cwe_ids": ["CWE-77"], "mitigation": "Input validation and sanitization"},
                {"name": "Excessive Data Exposure", "risk": "medium", "cwe_ids": ["CWE-200"], "mitigation": "Implement proper data filtering"},
            ],
            "database": [
                {"name": "SQL Injection", "risk": "critical", "cwe_ids": ["CWE-89"], "mitigation": "Use parameterized queries"},
                {"name": "Data Exfiltration", "risk": "critical", "cwe_ids": ["CWE-312"], "mitigation": "Encrypt sensitive data at rest"},
            ],
            "web": [
                {"name": "XSS", "risk": "high", "cwe_ids": ["CWE-79"], "mitigation": "Output encoding and Content Security Policy"},
                {"name": "CSRF", "risk": "medium", "cwe_ids": ["CWE-352"], "mitigation": "Implement anti-CSRF tokens"},
            ],
        }

        component_threats = threat_mappings.get(component_type, [])
        for t in component_threats:
            threats.append({
                **t,
                "component": component.get("name", "unknown"),
                "description": f"{t['name']} in {component.get('name', 'unknown')}: {component.get('description', '')}",
            })

        return threats

    def _analyze_data_flow_threats(self, flow: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze threats in data flow."""
        threats = []
        source = flow.get("source", "")
        destination = flow.get("destination", "")
        data_type = flow.get("data_type", "")

        # High-risk data types
        sensitive_types = ["pii", "credentials", "payment", "health"]

        if any(s in data_type.lower() for s in sensitive_types):
            threats.append({
                "name": f"Sensitive Data Exposure in {destination}",
                "risk": "critical" if "credentials" in data_type.lower() else "high",
                "cwe_ids": ["CWE-200", "CWE-312"],
                "mitigation": "Encrypt sensitive data in transit and at rest",
                "description": f"Data flow from {source} to {destination} handles sensitive {data_type} data",
            })

        return threats


# ============ Dependency Agent ============

class DependencyAgent(Phase3Agent):
    """Dependency vulnerability scanning agent."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str):
        super().__init__(AgentType.DEPENDENCY, message_bus, llm_router, project_id)

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute dependency scanning task."""
        action = task.input_data.get("action", "scan")

        if action == "scan":
            return await self.scan_dependencies(task.input_data)
        elif action == "check":
            return await self.check_vulnerability(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def scan_dependencies(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Scan dependencies for known vulnerabilities."""
        dependencies = input_data.get("dependencies", [])
        ecosystem = input_data.get("ecosystem", "python")  # python, npm, maven, etc.

        vulnerable_deps = []
        scanned_count = 0

        for dep in dependencies:
            scanned_count += 1
            name = dep.get("name", "")
            version = dep.get("version", "")

            # Check for known vulnerable versions (simulated)
            # In production, integrate with actual vulnerability databases
            vulnerability = self._check_known_vulnerabilities(name, version, ecosystem)

            if vulnerability:
                vulnerable_deps.append({
                    "name": name,
                    "version": version,
                    "vulnerability": vulnerability["id"],
                    "severity": vulnerability["severity"],
                    "description": vulnerability["description"],
                    "remediation": vulnerability["remediation"],
                })

                # Create finding
                await self.create_finding(
                    title=f"Vulnerable dependency: {name}@{version}",
                    severity=Severity.HIGH if vulnerability["severity"] == "high" else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"{name}@{version} has known vulnerability: {vulnerability['id']}",
                    evidence_data=vulnerability,
                    remediation=vulnerability["remediation"],
                    cwe_ids=["CWE-1104"],  # Unmaintained Component
                )

        return {
            "status": "completed",
            "total_scanned": scanned_count,
            "vulnerabilities_found": len(vulnerable_deps),
            "vulnerable_dependencies": vulnerable_deps,
            "summary": {
                "critical": len([v for v in vulnerable_deps if v["severity"] == "critical"]),
                "high": len([v for v in vulnerable_deps if v["severity"] == "high"]),
                "medium": len([v for v in vulnerable_deps if v["severity"] == "medium"]),
            },
        }

    async def check_vulnerability(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Check a specific dependency for vulnerabilities."""
        name = input_data.get("name", "")
        version = input_data.get("version", "")
        ecosystem = input_data.get("ecosystem", "python")

        vulnerability = self._check_known_vulnerabilities(name, version, ecosystem)

        if vulnerability:
            return {
                "status": "vulnerable",
                "name": name,
                "version": version,
                "vulnerability": vulnerability,
            }
        return {
            "status": "safe",
            "name": name,
            "version": version,
        }

    def _check_known_vulnerabilities(self, name: str, version: str, ecosystem: str) -> dict[str, Any] | None:
        """Check for known vulnerabilities (simulated CVE lookup)."""
        # This is a simulation - in production, integrate with:
        # - PyPI Security API
        # - GitHub Advisory Database
        # - NPM Security API
        # - Snyk, Dependabot, or similar services

        # Common vulnerable patterns (for demo purposes)
        known_vulns = {
            "django": {
                "versions": ["<3.2", "<4.0"],
                "cve": "CVE-2021-44420",
                "severity": "high",
                "description": "Potential bypass of an upstream access control",
            },
            "requests": {
                "versions": ["<2.28.0"],
                "cve": "CVE-2023-32681",
                "severity": "medium",
                "description": "Unintended leak of Proxy-Authorization header",
            },
            "lodash": {
                "versions": ["<4.17.21"],
                "cve": "CVE-2021-23337",
                "severity": "high",
                "description": "Command injection via template string",
            },
        }

        if name.lower() in known_vulns:
            vuln_info = known_vulns[name.lower()]
            # In real implementation, compare actual version against vuln versions
            return {
                "id": vuln_info["cve"],
                "severity": vuln_info["severity"],
                "description": vuln_info["description"],
                "remediation": f"Upgrade {name} to latest version",
            }

        return None


# ============ Debate Engine ============

class DebateAgent(Phase3Agent):
    """5-agent adversarial debate engine for finding validation."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str):
        super().__init__(AgentType.DEBATE, message_bus, llm_router, project_id)

        # Define the 5 debate roles
        self.roles = {
            "advocate": "Promotes the finding, provides supporting evidence",
            "skeptic": "Challenges the finding, looks for false positives",
            "analyst": "Analyzes technical accuracy and completeness",
            "attacker": "Attempts to exploit and find weaknesses in the finding",
            "synthesizer": "Weighs all arguments and provides final verdict",
        }

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute debate on a finding."""
        action = task.input_data.get("action", "debate")

        if action == "debate":
            return await self.conduct_debate(task.input_data)
        elif action == "verdict":
            return await self.render_verdict(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def conduct_debate(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Conduct adversarial debate on a finding."""
        finding = input_data.get("finding", {})
        finding_id = finding.get("id", str(uuid.uuid4()))

        # Debate rounds
        debate_transcript = []

        # Round 1: Advocate presents
        advocate_args = await self._advocate_presentation(finding)
        debate_transcript.append({"role": "advocate", "round": 1, "argument": advocate_args})

        # Round 2: Skeptic challenges
        skeptic_challenges = await self._skeptic_challenge(finding)
        debate_transcript.append({"role": "skeptic", "round": 2, "challenges": skeptic_challenges})

        # Round 3: Technical analysis
        technical_analysis = await self._technical_analysis(finding)
        debate_transcript.append({"role": "analyst", "round": 3, "analysis": technical_analysis})

        # Round 4: Attack simulation
        attack_results = await self._attack_simulation(finding)
        debate_transcript.append({"role": "attacker", "round": 4, "results": attack_results})

        # Round 5: Synthesis
        synthesis = await self._synthesize(finding, debate_transcript)
        debate_transcript.append({"role": "synthesizer", "round": 5, "synthesis": synthesis})

        # Determine verdict
        verdict = self._determine_verdict(debate_transcript)

        return {
            "status": "completed",
            "finding_id": finding_id,
            "debate_transcript": debate_transcript,
            "verdict": verdict,
        }

    async def render_verdict(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Render final verdict on a debated finding."""
        debate_results = input_data.get("debate_results", {})
        transcript = debate_results.get("debate_transcript", [])

        synthesis_data = next((t["synthesis"] for t in transcript if t["role"] == "synthesizer"), {})

        return {
            "finding_id": input_data.get("finding_id", ""),
            "verdict": debate_results.get("verdict", "NEEDS_REVIEW"),
            "confidence_adjustment": synthesis_data.get("confidence_change", "none"),
            "severity_adjustment": synthesis_data.get("severity_change", "none"),
            "recommendations": synthesis_data.get("recommendations", []),
        }

    async def _advocate_presentation(self, finding: dict[str, Any]) -> str:
        """Advocate presents supporting arguments for the finding."""
        prompt = f"""As an advocate, present strong arguments supporting this security finding:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Description: {finding.get('description', '')}

Provide:
1. Why this finding is valid and important
2. Supporting evidence from the data
3. Potential real-world impact if exploited
4. How an attacker could leverage this

Be persuasive but technically accurate.
"""

        return await self._get_llm_response(prompt)

    async def _skeptic_challenge(self, finding: dict[str, Any]) -> list[str]:
        """Skeptic challenges the finding, looking for weaknesses."""
        prompt = f"""As a skeptic, critically analyze this security finding and identify potential issues:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Description: {finding.get('description', '')}

Identify:
1. Potential false positive indicators
2. Missing context that could change interpretation
3. Why this might not be exploitable in practice
4. What additional evidence would be needed to validate

Be rigorous and challenge assumptions.
"""

        response = await self._get_llm_response(prompt)
        # Parse into individual challenges
        challenges = [c.strip() for c in response.split("\n") if c.strip()]
        return challenges[:5]  # Return top 5 challenges

    async def _technical_analysis(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Technical analyst reviews accuracy and completeness."""
        prompt = f"""As a technical analyst, assess the technical accuracy of this finding:

Title: {finding.get('title', 'Unknown')}
CWE: {finding.get('cwe_ids', [])}
Evidence: {finding.get('evidence', [])}

Evaluate:
1. Is the CWE classification correct?
2. Is the technical description accurate?
3. Are the affected components correctly identified?
4. Is the remediation actionable and correct?

Provide specific technical feedback.
"""

        response = await self._get_llm_response(prompt)
        # Calculate accuracy score based on response quality indicators
        # Use elif for proper priority: incorrect > partially > default > correct
        accuracy_score = 0.5  # Default
        response_lower = response.lower()
        if "incorrect" in response_lower or "wrong" in response_lower:
            accuracy_score = 0.4
        elif "partially" in response_lower:
            accuracy_score = 0.65
        elif "correct" in response_lower and "inaccurate" not in response_lower:
            accuracy_score = 0.85
        return {"analysis": response, "accuracy_score": accuracy_score}

    async def _attack_simulation(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Attacker attempts to exploit or disprove the finding."""
        prompt = f"""As an attacker, attempt to exploit this security finding:

Title: {finding.get('title', 'Unknown')}
Description: {finding.get('description', '')}

Simulate:
1. How would you actually exploit this?
2. What prerequisites are needed?
3. What defenses might already exist?
4. Can you construct a working exploit concept?

Be creative but realistic about exploitation conditions.
"""

        response = await self._get_llm_response(prompt)
        # Determine exploitability based on LLM response analysis
        exploitable = False
        complexity = "high"
        response_lower = response.lower()
        # Check for affirmative indicators, avoiding false positives like "not exploitable"
        if ("exploitable" in response_lower and "not exploitable" not in response_lower) or "can be exploited" in response_lower:
            exploitable = True
        # Determine complexity
        if "low complexity" in response_lower or "trivial" in response_lower:
            complexity = "low"
        elif "medium complexity" in response_lower or "moderate" in response_lower:
            complexity = "medium"
        return {
            "simulation": response,
            "exploitable": exploitable,
            "complexity": complexity,
        }

    async def _synthesize(self, finding: dict[str, Any], transcript: list[dict]) -> dict[str, Any]:
        """Synthesizer weighs all arguments and provides verdict."""
        # Get key points from each role
        advocate = next((t["argument"] for t in transcript if t["role"] == "advocate"), "")
        skeptic_points = next((t["challenges"] for t in transcript if t["role"] == "skeptic"), [])
        analyst = next((t["analysis"] for t in transcript if t["role"] == "analyst"), {})
        attacker = next((t["results"] for t in transcript if t["role"] == "attacker"), {})

        prompt = f"""As a synthesizer, weigh the following arguments about this security finding:

ADVOCATE: {advocate}

SKEPTIC: {skeptic_points}

ANALYST: {analyst}

ATTACKER: {attacker}

Determine:
1. Should this finding be promoted, rejected, or needs more review?
2. Should confidence or severity be adjusted?
3. What recommendations do you have?

Provide a clear verdict and reasoning.
"""

        response = await self._get_llm_response(prompt)

        return {
            "synthesis": response,
            "confidence_change": "increase" if "promote" in response.lower() else "decrease" if "reject" in response.lower() else "none",
            "severity_change": "increase" if "critical" in response.lower() else "decrease" if "low" in response.lower() else "none",
            "recommendations": ["Review and implement remediation", "Validate in staging environment"],
        }

    def _determine_verdict(self, transcript: list[dict]) -> dict[str, Any]:
        """Determine the final verdict based on debate."""
        # Count positive vs negative indicators
        synthesis_data = transcript[-1] if transcript else {}
        synthesis_text = str(synthesis_data.get("synthesis", "")).lower()

        if "promote" in synthesis_text or "valid" in synthesis_text:
            verdict = "PROMOTE"
            confidence_adjustment = "increase"
        elif "reject" in synthesis_text or "false positive" in synthesis_text:
            verdict = "REJECT"
            confidence_adjustment = "decrease"
        else:
            verdict = "NEEDS_REVIEW"
            confidence_adjustment = "none"

        return {
            "verdict": verdict,
            "confidence_adjustment": confidence_adjustment,
            "final_summary": synthesis_data.get("synthesis", "Debate completed."),
        }

    async def _get_llm_response(self, prompt: str) -> str:
        """Get response from LLM."""
        if not self.llm_router:
            return "LLM not configured - using fallback reasoning"

        try:
            messages = [LLMMessage(role=MessageRole.USER, content=prompt)]
            response = await self.llm_router.complete(messages, task_type="reasoning")
            return response.content
        except Exception as e:
            logger.error("llm_debate_failed", error=str(e))
            return f"Error getting LLM response: {e!s}"


# ============ Agent Factory ============

def create_phase3_agent(
    agent_type: AgentType,
    message_bus: MessageBus,
    llm_router: MultiProviderRouter,
    project_id: str,
    **kwargs,
) -> Phase3Agent:
    """Factory function to create Phase 3 agents."""
    agents = {
        AgentType.RECON: ReconAgent,
        AgentType.CODE_REVIEW: CodeReviewAgent,
        AgentType.THREAT_MODELING: ThreatModelingAgent,
        AgentType.DEPENDENCY: DependencyAgent,
        AgentType.DEBATE: DebateAgent,
    }

    agent_class = agents.get(agent_type)
    if not agent_class:
        raise ValueError(f"Unknown agent type: {agent_type}")

    return agent_class(message_bus, llm_router, project_id, **kwargs)
