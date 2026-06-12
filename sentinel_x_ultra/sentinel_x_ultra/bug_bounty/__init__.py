"""
Bug Bounty & Security Research System — Multi-Agent Framework v7.0.
Enterprise-grade autonomous security research platform with 10 specialized agents.

Built per specification:
- Foundational Principles (Legal & Ethical, QA, Scope Enforcement)
- 10 Agent Subsystems (URL Parser → Policy Enforcer → Scope Guardian → ... → Report Generation)
- Decision Hierarchy (5 levels, absolute priority order)
- Agent-Tool Integration (25+ tools automatically used by agents)
"""

from .system_prompts import (
    FOUNDATIONAL_PRINCIPLES,
    AGENT_ARCHITECTURE,
    DECISION_HIERARCHY,
    get_full_system_prompt,
)
from .llm_provider import (
    LLMProvider,
    LLMConfig,
    LLMProviderType,
    LLMAnalysis,
    CVSSAssessment,
    VulnerabilityHypothesis,
    get_llm_provider,
)
from .url_parser import URLParserAgent, ProgramIntelligence
from .policy_enforcer import (
    PolicyEnforcerAgent,
    PolicyEnforcementResult,
    PolicyRule,
    PolicyDecision,
    PolicyDecisionOutput,
    ScopeStatus,
    AssetEligibility,
    TestingCompliance,
    VulnEligibility,
    EvidenceTier,
    DuplicateRisk,
)
from .scope_guardian import (
    ScopeGuardianAgent,
    ScopeCheckResult,
    ScopeAuthorization,
    AuthorizationState,
    OwnershipStatus,
    AssetType,
    RiskLevel,
)
from .passive_intel import (
    PassiveIntelligenceAgent,
    PassiveIntelResult,
    DiscoveredAsset,
    AssetClass,
    ReliabilityLevel,
    AssetPriority,
)
from .active_enum import ActiveEnumerationAgent, ActiveEnumResult
from .vuln_scanner import VulnerabilityScannerAgent, TestResult
from .validation_engine import ValidationEngineAgent, ValidationResult, NormalizedFinding
from .exploitation import ExploitationAgent, ProofOfConcept
from .analysis import (
    AnalysisAgent,
    FindingAnalysis,
    DetailedAnalysis,
    CVSSEntry,
    CVSSMetrics,
    CWEInfo,
    CWEAlternative,
    OWASPInfo,
    OWASPAlternative,
    CVSSScore,
)
from .report_generation import ReportGenerationAgent, VulnerabilityReport
from .agent_memory import AgentMemory, MemoryEntry
from .data_sources import (
    DataSourceAggregator,
    ShodanClient,
    CensysClient,
    SecurityTrailsClient,
    URLScanClient,
    DataSourceResult,
)
from .execution_engine import (
    ParallelExecutor,
    ResultCache,
    RateLimiter,
    TimeoutManager,
    get_parallel_executor,
    get_result_cache,
    get_rate_limiter,
    get_timeout_manager,
)
from .security_guard import (
    ScopeValidator,
    OutputSanitizer,
    EthicalGuard,
    ResourceLimiter,
    ScopeValidationResult,
    SanitizationResult,
    EthicalCheckResult,
    ResourceLimitResult,
    get_scope_validator,
    get_output_sanitizer,
    get_ethical_guard,
    get_resource_limiter,
)
from .webhook import (
    WebhookManager,
    WebhookConfig,
    WebhookDelivery,
    WEBHOOK_EVENT_POLICY_DECISION,
    WEBHOOK_EVENT_PIPELINE_COMPLETED,
)
from .orchestrator import BugBountyOrchestrator, BugBountyPipelineResult
from ..agent_tool_integration import AgentToolIntegration, get_agent_tool_integration, INTEGRATION_PLAN

__all__ = [
    "FOUNDATIONAL_PRINCIPLES",
    "AGENT_ARCHITECTURE",
    "DECISION_HIERARCHY",
    "get_full_system_prompt",
    "LLMProvider",
    "LLMConfig",
    "LLMProviderType",
    "LLMAnalysis",
    "CVSSAssessment",
    "VulnerabilityHypothesis",
    "get_llm_provider",
    "URLParserAgent",
    "ProgramIntelligence",
    "PolicyEnforcerAgent",
    "PolicyEnforcementResult",
    "PolicyRule",
    "PolicyDecision",
    "PolicyDecisionOutput",
    "ScopeStatus",
    "AssetEligibility",
    "TestingCompliance",
    "VulnEligibility",
    "EvidenceTier",
    "DuplicateRisk",
    "ScopeGuardianAgent",
    "ScopeCheckResult",
    "ScopeAuthorization",
    "AuthorizationState",
    "OwnershipStatus",
    "AssetType",
    "RiskLevel",
    "PassiveIntelligenceAgent",
    "PassiveIntelResult",
    "DiscoveredAsset",
    "AssetClass",
    "ReliabilityLevel",
    "AssetPriority",
    "ActiveEnumerationAgent",
    "ActiveEnumResult",
    "VulnerabilityScannerAgent",
    "TestResult",
    "ValidationEngineAgent",
    "ValidationResult",
    "NormalizedFinding",
    "ExploitationAgent",
    "ProofOfConcept",
    "AnalysisAgent",
    "FindingAnalysis",
    "DetailedAnalysis",
    "CVSSEntry",
    "CVSSMetrics",
    "CWEInfo",
    "CWEAlternative",
    "OWASPInfo",
    "OWASPAlternative",
    "CVSSScore",
    "ReportGenerationAgent",
    "VulnerabilityReport",
    "AgentMemory",
    "MemoryEntry",
    "DataSourceAggregator",
    "ShodanClient",
    "CensysClient",
    "SecurityTrailsClient",
    "URLScanClient",
    "DataSourceResult",
    "ParallelExecutor",
    "ResultCache",
    "RateLimiter",
    "TimeoutManager",
    "get_parallel_executor",
    "get_result_cache",
    "get_rate_limiter",
    "get_timeout_manager",
    "ScopeValidator",
    "OutputSanitizer",
    "EthicalGuard",
    "ResourceLimiter",
    "ScopeValidationResult",
    "SanitizationResult",
    "EthicalCheckResult",
    "ResourceLimitResult",
    "get_scope_validator",
    "get_output_sanitizer",
    "get_ethical_guard",
    "get_resource_limiter",
    "BugBountyOrchestrator",
    "BugBountyPipelineResult",
    "WebhookManager",
    "WebhookConfig",
    "WebhookDelivery",
    "WEBHOOK_EVENT_POLICY_DECISION",
    "WEBHOOK_EVENT_PIPELINE_COMPLETED",
    "AgentToolIntegration",
    "get_agent_tool_integration",
    "INTEGRATION_PLAN",
]
