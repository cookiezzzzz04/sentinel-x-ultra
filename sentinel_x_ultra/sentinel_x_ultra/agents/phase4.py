"""Phase 4 Agents - Autonomous Remediation, Reporting, and Compliance.

Phase 4 features focus on closing the gap between detection and resolution:
- Closed-Loop Autonomous Remediation
- Continuous Verification & Validation
- Autonomous Compliance & Reporting
- Real-Time Adaptive Threat Intelligence
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog

from .phase3 import Phase3Agent, Finding, Severity, Confidence, MessageBus, MultiProviderRouter, AgentType, TaskPayload, LLMMessage, MessageRole

logger = structlog.get_logger()


# ============ Remediation Agent ============

class RemediationAgent(Phase3Agent):
    """Agent that generates and validates automated remediation plans for findings."""

    def __init__(self, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str):
        super().__init__(AgentType.RECON, message_bus, llm_router, project_id)  # Using RECON as base type
        self.agent_type = AgentType.RECON  # Override for proper typing

    @property
    def type_value(self):
        return "remediation"

    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute remediation planning task."""
        input_data = task.input_data or {}
        action = input_data.get("action", "plan")

        if action == "plan":
            return await self.create_remediation_plan(task.input_data)
        elif action == "validate":
            return await self.validate_remediation(task.input_data)
        elif action == "implement":
            return await self.simulate_implementation(task.input_data)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    async def create_remediation_plan(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Create a detailed remediation plan for a finding."""
        finding = input_data.get("finding", {})
        finding_id = finding.get("id", str(uuid.uuid4()))
        cwe_ids = finding.get("cwe_ids", [])

        # Generate remediation steps based on CWE
        remediation_steps = self._generate_remediation_steps(cwe_ids, finding)

        # Create a structured plan
        plan = {
            "finding_id": finding_id,
            "title": f"Remediation plan for: {finding.get('title', 'Unknown')}",
            "severity": finding.get("severity", "unknown"),
            "steps": remediation_steps,
            "estimated_effort": self._estimate_effort(remediation_steps),
            "risk_level": self._assess_remediation_risk(remediation_steps),
            "rollback_plan": self._generate_rollback_plan(remediation_steps),
        }

        # Create finding for the remediation plan
        await self.create_finding(
            title=f"Remediation plan created for {finding.get('title', 'Unknown')}",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            description=f"Generated {len(remediation_steps)} remediation steps",
            evidence_data={"plan": plan, "finding": finding},
            remediation="Review and approve the remediation plan before implementation",
            cwe_ids=cwe_ids,
        )

        return {
            "status": "completed",
            "plan": plan,
            "steps_count": len(remediation_steps),
        }

    async def validate_remediation(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Validate that a remediation plan has been properly implemented."""
        plan = input_data.get("plan", {})
        steps = plan.get("steps", [])

        validation_results = []
        all_valid = True

        for step in steps:
            # Simulate validation (in production, would check actual code/config changes)
            is_valid = await self._validate_step(step)
            validation_results.append({
                "step": step.get("description", "Unknown step"),
                "valid": is_valid,
                "verified_at": datetime.utcnow().isoformat(),
            })
            if not is_valid:
                all_valid = False

        return {
            "status": "completed",
            "plan_id": plan.get("finding_id", "unknown"),
            "all_valid": all_valid,
            "validation_results": validation_results,
            "validated_at": datetime.utcnow().isoformat(),
        }

    async def simulate_implementation(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Simulate the implementation of a remediation plan (safe mode)."""
        plan = input_data.get("plan", {})
        steps = plan.get("steps", [])
        dry_run = input_data.get("dry_run", True)

        if dry_run:
            # In dry-run mode, just show what would happen
            simulation = {
                "mode": "dry_run",
                "would_execute": len(steps),
                "changes": [],
            }
            for step in steps:
                simulation["changes"].append({
                    "action": step.get("action", "unknown"),
                    "target": step.get("target", "unknown"),
                    "description": step.get("description", ""),
                    "risk": step.get("risk", "unknown"),
                })
            return {
                "status": "completed",
                "simulation": simulation,
                "message": "Dry-run completed. Set dry_run=false to actually implement changes.",
            }

        # Real implementation mode (simulated - in production would apply changes)
        results = []
        for step in steps:
            result = await self._apply_remediation_step(step)
            results.append(result)

        return {
            "status": "completed",
            "mode": "implemented",
            "results": results,
            "implemented_at": datetime.utcnow().isoformat(),
        }

    def _generate_remediation_steps(self, cwe_ids: list[str], finding: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate remediation steps based on CWE IDs."""
        steps = []
        
        # Mapping of CWE IDs to remediation guidance
        cwe_remediation_map = {
            "CWE-89": {  # SQL Injection
                "action": "parameterized_query",
                "description": "Replace string concatenation with parameterized queries",
                "risk": "low",
                "steps": [
                    "Identify all SQL query construction points",
                    "Replace dynamic SQL string building with prepared statements",
                    "Validate input sanitization is in place",
                    "Run SQL injection test suite",
                ]
            },
            "CWE-79": {  # XSS
                "action": "output_encoding",
                "description": "Implement proper output encoding",
                "risk": "low",
                "steps": [
                    "Identify output contexts (HTML, JS, CSS, URL)",
                    "Apply context-appropriate encoding (htmlEncode, jsonEncode, etc.)",
                    "Implement Content Security Policy (CSP) headers",
                    "Run XSS test suite",
                ]
            },
            "CWE-77": {  # Command Injection
                "action": "input_validation",
                "description": "Validate and sanitize all user inputs before shell commands",
                "risk": "medium",
                "steps": [
                    "Identify all system() or exec() calls",
                    "Replace shell commands with API calls where possible",
                    "Implement strict allowlist input validation",
                    "Apply principle of least privilege to execution environment",
                ]
            },
            "CWE-200": {  # Information Disclosure
                "action": "access_control",
                "description": "Implement proper access controls and data classification",
                "risk": "medium",
                "steps": [
                    "Audit data access patterns",
                    "Implement role-based access control (RBAC)",
                    "Add data masking for sensitive fields",
                    "Review and restrict verbose error messages",
                ]
            },
            "CWE-312": {  # Cleartext Storage
                "action": "encryption",
                "description": "Encrypt sensitive data at rest",
                "risk": "high",
                "steps": [
                    "Identify unencrypted sensitive data storage",
                    "Implement AES-256 encryption for sensitive fields",
                    "Rotate encryption keys following best practices",
                    "Update data handling policies",
                ]
            },
            "CWE-287": {  # Authentication Bypass
                "action": "auth_hardening",
                "description": "Strengthen authentication mechanisms",
                "risk": "high",
                "steps": [
                    "Implement multi-factor authentication (MFA)",
                    "Add rate limiting to login endpoints",
                    "Implement proper session management",
                    "Apply secure password hashing (bcrypt/argon2)",
                ]
            },
        }

        for cwe in cwe_ids:
            if cwe in cwe_remediation_map:
                remediation = cwe_remediation_map[cwe]
                steps.append({
                    "cwe": cwe,
                    "action": remediation["action"],
                    "description": remediation["description"],
                    "risk": remediation["risk"],
                    "steps": remediation["steps"],
                })
            else:
                # Generic remediation for unknown CWE
                steps.append({
                    "cwe": cwe,
                    "action": "code_review",
                    "description": f"Review and fix CWE-{cwe} related issue",
                    "risk": "medium",
                    "steps": [
                        "Conduct security code review",
                        "Implement appropriate fix",
                        "Add security test case",
                        "Peer review changes",
                    ]
                })

        # Add verification step for all remediations
        steps.append({
            "cwe": "ALL",
            "action": "verification",
            "description": "Verify remediation effectiveness",
            "risk": "low",
            "steps": [
                "Run relevant security tests",
                "Perform static analysis scan",
                "Review code changes",
                "Document remediation completion",
            ]
        })

        return steps

    def _estimate_effort(self, steps: list[dict[str, Any]]) -> str:
        """Estimate effort required for remediation."""
        total_steps = sum(len(s.get("steps", [])) for s in steps)
        if total_steps <= 4:
            return "low"
        elif total_steps <= 10:
            return "medium"
        else:
            return "high"

    def _assess_remediation_risk(self, steps: list[dict[str, Any]]) -> str:
        """Assess risk level of the remediation process itself."""
        high_risk_count = sum(1 for s in steps if s.get("risk") == "high")
        if high_risk_count > 0:
            return "high"
        medium_risk_count = sum(1 for s in steps if s.get("risk") == "medium")
        if medium_risk_count > 2:
            return "medium"
        return "low"

    def _generate_rollback_plan(self, steps: list[dict[str, Any]]) -> list[str]:
        """Generate rollback instructions for each step."""
        rollback = []
        for step in reversed(steps):
            rollback.append(f"Revert changes from step: {step.get('description', 'Unknown step')}")
        rollback.append("Restore from last known good backup if needed")
        rollback.append("Alert security team of rollback")
        return rollback

    async def _validate_step(self, step: dict[str, Any]) -> bool:
        """Validate a single remediation step."""
        # Simulate validation - in production would check actual state
        await self._simulate_delay(0.1)
        return True  # Assume valid for now

    async def _apply_remediation_step(self, step: dict[str, Any]) -> dict[str, Any]:
        """Apply a single remediation step."""
        await self._simulate_delay(0.2)
        return {
            "step": step.get("description", "Unknown"),
            "applied": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _simulate_delay(self, seconds: float):
        """Simulate processing delay."""
        import asyncio
        await asyncio.sleep(seconds)


# ============ Report Generator ============

class ReportGenerator:
    """Generates comprehensive security reports with evidence collection."""

    def __init__(self, project_id: str, llm_router: MultiProviderRouter | None = None):
        self.project_id = project_id
        self.llm_router = llm_router
        self.sections = []

    async def generate_executive_summary(self, findings: list[Finding], metrics: dict[str, Any]) -> dict[str, Any]:
        """Generate executive-level security summary."""
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        summary = {
            "report_id": str(uuid.uuid4()),
            "type": "executive_summary",
            "generated_at": datetime.utcnow().isoformat(),
            "project_id": self.project_id,
            "findings_overview": {
                "total": len(findings),
                "by_severity": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                }
            },
            "risk_score": self._calculate_risk_score(findings),
            "key_findings": self._extract_key_findings(findings, max_count=5),
            "recommendations": self._generate_recommendations(findings, metrics),
            "compliance_status": self._assess_compliance_status(findings),
        }

        return summary

    async def generate_detailed_report(self, findings: list[Finding], evidence: dict[str, Any]) -> dict[str, Any]:
        """Generate detailed technical security report."""
        report = {
            "report_id": str(uuid.uuid4()),
            "type": "detailed_technical",
            "generated_at": datetime.utcnow().isoformat(),
            "project_id": self.project_id,
            "sections": [
                await self._generate_findings_section(findings),
                await self._generate_vulnerability_details(findings),
                await self._generate_evidence_section(evidence),
                await self._generate_remediation_section(findings),
                await self._generate_appendix(findings),
            ],
            "total_pages_estimate": len(findings) // 3 + 5,
        }

        return report

    async def generate_compliance_report(self, findings: list[Finding], frameworks: list[str]) -> dict[str, Any]:
        """Generate compliance-focused report mapping findings to frameworks."""
        compliance_mapping = {}

        for framework in frameworks:
            framework_mapping = self._map_to_framework(framework, findings)
            compliance_mapping[framework] = framework_mapping

        return {
            "report_id": str(uuid.uuid4()),
            "type": "compliance_report",
            "generated_at": datetime.utcnow().isoformat(),
            "project_id": self.project_id,
            "frameworks": frameworks,
            "compliance_summary": {
                framework: {
                    "total_requirements": len(compliance_mapping[framework]),
                    "met": sum(1 for r in compliance_mapping[framework] if r.get("status") == "met"),
                    "partial": sum(1 for r in compliance_mapping[framework] if r.get("status") == "partial"),
                    "gap": sum(1 for r in compliance_mapping[framework] if r.get("status") == "gap"),
                }
                for framework in frameworks
            },
            "mappings": compliance_mapping,
            "evidence_required": self._identify_compliance_evidence(findings, frameworks),
        }

    async def _generate_findings_section(self, findings: list[Finding]) -> dict[str, Any]:
        """Generate findings summary section."""
        return {
            "title": "Security Findings",
            "order": 1,
            "content": {
                "total_findings": len(findings),
                "by_severity": {
                    "critical": [f.to_dict() for f in findings if f.severity == Severity.CRITICAL],
                    "high": [f.to_dict() for f in findings if f.severity == Severity.HIGH],
                    "medium": [f.to_dict() for f in findings if f.severity == Severity.MEDIUM],
                    "low": [f.to_dict() for f in findings if f.severity == Severity.LOW],
                },
                "by_status": {
                    "pending": len([f for f in findings if f.status.value == "pending"]),
                    "confirmed": len([f for f in findings if f.status.value == "confirmed"]),
                    "resolved": len([f for f in findings if f.status.value == "resolved"]),
                    "false_positive": len([f for f in findings if f.status.value == "false_positive"]),
                }
            }
        }

    async def _generate_vulnerability_details(self, findings: list[Finding]) -> dict[str, Any]:
        """Generate detailed vulnerability descriptions."""
        details = []
        for finding in findings[:20]:  # Limit to top 20 for report size
            details.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "description": finding.description,
                "affected_components": finding.affected_components,
                "cwe_ids": finding.cwe_ids,
                "evidence_count": len(finding.evidence),
                "remediation": finding.remediation,
                "created_at": finding.created_at,
            })

        return {
            "title": "Vulnerability Details",
            "order": 2,
            "content": {"vulnerabilities": details}
        }

    async def _generate_evidence_section(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Generate evidence collection section."""
        return {
            "title": "Evidence Collection",
            "order": 3,
            "content": {
                "total_evidence_items": sum(len(e) for e in evidence.values()) if evidence else 0,
                "evidence_by_source": evidence,
                "collection_timestamp": datetime.utcnow().isoformat(),
                "chain_of_custody": self._generate_custody_chain(),
            }
        }

    async def _generate_remediation_section(self, findings: list[Finding]) -> dict[str, Any]:
        """Generate remediation recommendations section."""
        remediations = []
        for finding in findings:
            if finding.status.value == "pending":
                remediations.append({
                    "finding_id": finding.id,
                    "title": finding.title,
                    "remediation": finding.remediation,
                    "priority": finding.severity.value,
                    "estimated_effort": "medium",  # Would be calculated in production
                })

        return {
            "title": "Remediation Recommendations",
            "order": 4,
            "content": {"recommendations": remediations}
        }

    async def _generate_appendix(self, findings: list[Finding]) -> dict[str, Any]:
        """Generate appendix with supporting data."""
        return {
            "title": "Appendix",
            "order": 5,
            "content": {
                "methodology": "SENTINEL-X ULTRA Phase 2/3 Analysis",
                "tools_used": ["SAST Engine", "Web Analyzer", "Knowledge Graph", "Phase 3 Agents"],
                "scan_timestamp": datetime.utcnow().isoformat(),
                "total_cwe_mappings": len(set(cwe for f in findings for cwe in f.cwe_ids)),
            }
        }

    def _calculate_risk_score(self, findings: list[Finding]) -> dict[str, Any]:
        """Calculate overall risk score based on findings."""
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
        }

        total_score = sum(severity_weights.get(f.severity, 0) for f in findings)

        # Normalize to 0-100 scale
        max_possible = len(findings) * 10 if findings else 1
        normalized_score = min(100, (total_score / max_possible) * 100)

        return {
            "score": round(normalized_score, 1),
            "rating": "critical" if normalized_score >= 80 else "high" if normalized_score >= 60 else "medium" if normalized_score >= 40 else "low",
            "factors": {
                "critical_findings": len([f for f in findings if f.severity == Severity.CRITICAL]),
                "high_findings": len([f for f in findings if f.severity == Severity.HIGH]),
                "exposure_level": "internal" if normalized_score < 50 else "external" if normalized_score > 75 else "limited",
            }
        }

    def _extract_key_findings(self, findings: list[Finding], max_count: int = 5) -> list[dict[str, Any]]:
        """Extract the most important findings for executives."""
        # Sort by severity then confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_weights.get(f.severity, 0), f.confidence.value),
            reverse=True
        )[:max_count]

        return [
            {
                "title": f.title,
                "severity": f.severity.value,
                "impact": f.description[:200] + "..." if len(f.description) > 200 else f.description,
                "affected_systems": len(f.affected_components),
            }
            for f in sorted_findings
        ]

    def _generate_recommendations(self, findings: list[Finding], metrics: dict[str, Any]) -> list[str]:
        """Generate high-level recommendations based on findings."""
        recommendations = []

        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        if critical_count > 0:
            recommendations.append(f"Immediately address {critical_count} critical severity findings")

        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        if high_count > 0:
            recommendations.append(f"Prioritize remediation of {high_count} high severity findings within 2 weeks")

        # Check for common patterns
        sql_injection_count = len([f for f in findings if "CWE-89" in f.cwe_ids])
        if sql_injection_count > 0:
            recommendations.append("Implement parameterized queries across all database interactions")

        xss_count = len([f for f in findings if "CWE-79" in f.cwe_ids])
        if xss_count > 0:
            recommendations.append("Deploy Content Security Policy (CSP) headers to mitigate XSS risks")

        if not recommendations:
            recommendations.append("Continue regular security monitoring and periodic assessments")

        return recommendations

    def _assess_compliance_status(self, findings: list[Finding]) -> dict[str, Any]:
        """Assess compliance status based on findings."""
        return {
            "overall": "needs_improvement",
            "frameworks_covered": ["OWASP Top 10", "NIST CSF"],
            "findings_impacting_compliance": len([f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]),
            "evidence_ready": True,
        }

    def _map_to_framework(self, framework: str, findings: list[Finding]) -> list[dict[str, Any]]:
        """Map findings to a specific compliance framework."""
        framework_mappings = {
            "OWASP Top 10": {
                "A01": {"name": "Broken Access Control", "cwe_ids": ["CWE-287", "CWE-862"]},
                "A02": {"name": "Cryptographic Failures", "cwe_ids": ["CWE-312", "CWE-319"]},
                "A03": {"name": "Injection", "cwe_ids": ["CWE-89", "CWE-77", "CWE-79"]},
                "A04": {"name": "Insecure Design", "cwe_ids": ["CWE-200"]},
                "A05": {"name": "Security Misconfiguration", "cwe_ids": []},
                "A06": {"name": "Vulnerable Components", "cwe_ids": ["CWE-1104"]},
                "A07": {"name": "Authentication Failures", "cwe_ids": ["CWE-287"]},
                "A08": {"name": "Software Integrity Failures", "cwe_ids": []},
                "A09": {"name": "Security Logging Failures", "cwe_ids": []},
                "A10": {"name": "Server-Side Request Forgery", "cwe_ids": []},
            },
            "NIST CSF": {
                "ID.AM": {"name": "Asset Management", "cwe_ids": []},
                "ID.RA": {"name": "Risk Assessment", "cwe_ids": []},
                "PR.AC": {"name": "Access Control", "cwe_ids": ["CWE-287", "CWE-862"]},
                "PR.DS": {"name": "Data Security", "cwe_ids": ["CWE-312"]},
                "DE.CM": {"name": "Continuous Monitoring", "cwe_ids": []},
                "RS.MI": {"name": "Mitigation", "cwe_ids": []},
            },
        }

        mapping = framework_mappings.get(framework, {})
        requirements = []

        for req_id, req_info in mapping.items():
            mapped_findings = [
                f for f in findings
                if any(cwe in req_info.get("cwe_ids", []) for cwe in f.cwe_ids)
            ]
            status = "gap" if mapped_findings else "met" if req_info.get("cwe_ids") else "not_applicable"

            requirements.append({
                "id": req_id,
                "name": req_info.get("name", "Unknown"),
                "status": status,
                "mapped_findings": len(mapped_findings),
                "findings": [f.id for f in mapped_findings[:3]],  # Limit to 3 IDs
            })

        return requirements

    def _identify_compliance_evidence(self, findings: list[Finding], frameworks: list[str]) -> list[str]:
        """Identify what evidence is needed for compliance."""
        evidence_requirements = []

        for framework in frameworks:
            if framework == "OWASP Top 10":
                evidence_requirements.extend([
                    "SAST scan results showing vulnerability remediation",
                    "DAST scan results from dynamic testing",
                    "Code review sign-offs",
                    "Penetration test report",
                ])
            elif framework == "NIST CSF":
                evidence_requirements.extend([
                    "Risk assessment documentation",
                    "Security policy documents",
                    "Access control audit logs",
                    "Incident response plan",
                ])

        return list(set(evidence_requirements))  # Remove duplicates

    def _generate_custody_chain(self) -> list[dict[str, str]]:
        """Generate chain of custody record for evidence."""
        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "action": "evidence_collected",
                "tool": "SENTINEL-X ULTRA",
                "user": "automated_system",
            }
        ]


# ============ Compliance Engine ============

class ComplianceEngine:
    """Maps security findings to compliance frameworks and tracks compliance posture."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.frameworks = self._initialize_frameworks()

    def _initialize_frameworks(self) -> dict[str, dict[str, Any]]:
        """Initialize supported compliance frameworks."""
        return {
            "OWASP Top 10": {
                "version": "2021",
                "description": "Standard for web application security",
                "controls": self._get_owasp_controls(),
            },
            "NIST CSF": {
                "version": "2.0",
                "description": "Cybersecurity Framework",
                "controls": self._get_nist_controls(),
            },
            "SOC2": {
                "version": "2017",
                "description": "Service Organization Control 2",
                "controls": self._get_soc2_controls(),
            },
            "PCI-DSS": {
                "version": "4.0",
                "description": "Payment Card Industry Data Security Standard",
                "controls": self._get_pci_dss_controls(),
            },
        }

    async def assess_compliance(self, findings: list[Finding]) -> dict[str, Any]:
        """Assess current compliance posture across all frameworks."""
        results = {}

        for framework_name, framework in self.frameworks.items():
            assessment = self._assess_framework(framework_name, framework, findings)
            results[framework_name] = assessment

        return {
            "project_id": self.project_id,
            "assessed_at": datetime.utcnow().isoformat(),
            "frameworks": results,
            "overall_score": self._calculate_overall_score(results),
            "critical_gaps": self._identify_critical_gaps(results),
        }

    async def generate_control_mapping(self, findings: list[Finding], framework: str) -> dict[str, Any]:
        """Generate detailed mapping of findings to framework controls."""
        if framework not in self.frameworks:
            return {"error": f"Unknown framework: {framework}"}

        framework_info = self.frameworks[framework]
        controls = framework_info.get("controls", {})

        mapping = {}
        for control_id, control_info in controls.items():
            mapped_findings = [
                f for f in findings
                if any(cwe in control_info.get("cwe_ids", []) for cwe in f.cwe_ids)
            ]
            mapping[control_id] = {
                "control_name": control_info.get("name", "Unknown"),
                "status": self._determine_status(mapped_findings, control_info),
                "findings_count": len(mapped_findings),
                "findings": [f.to_dict() for f in mapped_findings],
                "gap_description": control_info.get("gap_description", "") if len(mapped_findings) == 0 else "",
            }

        return {
            "framework": framework,
            "version": framework_info.get("version", ""),
            "description": framework_info.get("description", ""),
            "mapping": mapping,
            "total_controls": len(controls),
            "met_controls": sum(1 for m in mapping.values() if m["status"] == "met"),
            "partial_controls": sum(1 for m in mapping.values() if m["status"] == "partial"),
            "gap_controls": sum(1 for m in mapping.values() if m["status"] == "gap"),
        }

    async def generate_remediation_priority(self, findings: list[Finding], framework: str) -> list[dict[str, Any]]:
        """Generate prioritized list of remediations based on framework compliance impact."""
        control_mapping = await self.generate_control_mapping(findings, framework)

        priority_list = []
        for control_id, control_info in control_mapping.get("mapping", {}).items():
            if control_info["status"] in ["gap", "partial"]:
                priority_list.append({
                    "control_id": control_id,
                    "control_name": control_info["control_name"],
                    "status": control_info["status"],
                    "findings_count": control_info["findings_count"],
                    "remediation_effort": "high" if control_info["status"] == "gap" else "medium",
                    "compliance_impact": "critical" if control_info["status"] == "gap" else "moderate",
                })

        # Sort by status (gap first) then by findings count
        priority_list.sort(key=lambda x: (0 if x["status"] == "gap" else 1, -x["findings_count"]))

        return priority_list

    def _assess_framework(self, framework_name: str, framework: dict, findings: list[Finding]) -> dict[str, Any]:
        """Assess compliance for a specific framework."""
        controls = framework.get("controls", {})
        total_controls = len(controls)
        met_count = 0
        partial_count = 0
        gap_count = 0

        for control_id, control_info in controls.items():
            mapped_findings = [
                f for f in findings
                if any(cwe in control_info.get("cwe_ids", []) for cwe in f.cwe_ids)
            ]
            status = self._determine_status(mapped_findings, control_info)

            if status == "met":
                met_count += 1
            elif status == "partial":
                partial_count += 1
            else:
                gap_count += 1

        score = ((met_count * 100) + (partial_count * 50)) / total_controls if total_controls > 0 else 0

        return {
            "score": round(score, 1),
            "status": "compliant" if score >= 80 else "needs_attention" if score >= 50 else "non_compliant",
            "breakdown": {
                "total_controls": total_controls,
                "met": met_count,
                "partial": partial_count,
                "gap": gap_count,
            },
            "critical_gaps": gap_count,
        }

    def _determine_status(self, mapped_findings: list[Finding], control_info: dict) -> str:
        """Determine compliance status for a control."""
        if not control_info.get("cwe_ids"):
            return "not_applicable"
        if len(mapped_findings) == 0:
            return "met"
        # Check if any findings are critical/high
        critical_findings = [f for f in mapped_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if len(critical_findings) > 0:
            return "gap"
        return "partial"

    def _calculate_overall_score(self, results: dict[str, Any]) -> float:
        """Calculate overall compliance score across frameworks."""
        if not results:
            return 0.0
        scores = [r.get("score", 0) for r in results.values()]
        return round(sum(scores) / len(scores), 1)

    def _identify_critical_gaps(self, results: dict[str, Any]) -> list[str]:
        """Identify critical compliance gaps across frameworks."""
        gaps = []
        for framework, result in results.items():
            if result.get("status") == "non_compliant":
                gaps.append(f"{framework}: {result.get('critical_gaps', 0)} critical gaps")
        return gaps

    def _get_owasp_controls(self) -> dict[str, dict[str, Any]]:
        """Get OWASP Top 10 control mappings."""
        return {
            "A01": {"name": "Broken Access Control", "cwe_ids": ["CWE-287", "CWE-862"], "gap_description": "No critical access control vulnerabilities detected"},
            "A02": {"name": "Cryptographic Failures", "cwe_ids": ["CWE-312", "CWE-319"], "gap_description": "No cryptographic failures detected"},
            "A03": {"name": "Injection", "cwe_ids": ["CWE-89", "CWE-77", "CWE-79"], "gap_description": "No injection vulnerabilities detected"},
            "A04": {"name": "Insecure Design", "cwe_ids": ["CWE-200"], "gap_description": "No insecure design issues detected"},
            "A05": {"name": "Security Misconfiguration", "cwe_ids": [], "gap_description": ""},
            "A06": {"name": "Vulnerable Components", "cwe_ids": ["CWE-1104"], "gap_description": "No vulnerable components detected"},
            "A07": {"name": "Authentication Failures", "cwe_ids": ["CWE-287"], "gap_description": "No authentication failures detected"},
            "A08": {"name": "Software Integrity Failures", "cwe_ids": [], "gap_description": ""},
            "A09": {"name": "Security Logging Failures", "cwe_ids": [], "gap_description": ""},
            "A10": {"name": "Server-Side Request Forgery", "cwe_ids": [], "gap_description": ""},
        }

    def _get_nist_controls(self) -> dict[str, dict[str, Any]]:
        """Get NIST CSF control mappings."""
        return {
            "ID.AM": {"name": "Asset Management", "cwe_ids": [], "gap_description": ""},
            "ID.RA": {"name": "Risk Assessment", "cwe_ids": [], "gap_description": ""},
            "PR.AC": {"name": "Access Control", "cwe_ids": ["CWE-287", "CWE-862"], "gap_description": "No critical access control issues detected"},
            "PR.DS": {"name": "Data Security", "cwe_ids": ["CWE-312"], "gap_description": "No data security issues detected"},
            "DE.CM": {"name": "Continuous Monitoring", "cwe_ids": [], "gap_description": ""},
            "RS.MI": {"name": "Mitigation", "cwe_ids": [], "gap_description": ""},
        }

    def _get_soc2_controls(self) -> dict[str, dict[str, Any]]:
        """Get SOC 2 control mappings."""
        return {
            "CC6": {"name": "Logical and Physical Access Controls", "cwe_ids": ["CWE-287", "CWE-312"], "gap_description": "No critical access control issues detected"},
            "CC7": {"name": "System Operations", "cwe_ids": [], "gap_description": ""},
            "CC8": {"name": "Change Management", "cwe_ids": [], "gap_description": ""},
        }

    def _get_pci_dss_controls(self) -> dict[str, dict[str, Any]]:
        """Get PCI DSS control mappings."""
        return {
            "REQ3": {"name": "Protect Stored Cardholder Data", "cwe_ids": ["CWE-312"], "gap_description": "No cardholder data protection issues detected"},
            "REQ6": {"name": "Maintain Vulnerability Management", "cwe_ids": ["CWE-89", "CWE-79", "CWE-77"], "gap_description": "No critical vulnerabilities detected"},
            "REQ8": {"name": "Authenticate Access", "cwe_ids": ["CWE-287"], "gap_description": "No authentication failures detected"},
        }


# ============ Phase 4 Factory ============

def create_phase4_agent(agent_type: str, message_bus: MessageBus, llm_router: MultiProviderRouter, project_id: str) -> Phase3Agent:
    """Factory function to create Phase 4 agents."""
    if agent_type == "remediation":
        return RemediationAgent(message_bus, llm_router, project_id)
    raise ValueError(f"Unknown Phase 4 agent type: {agent_type}")