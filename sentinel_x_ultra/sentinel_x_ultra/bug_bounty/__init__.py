"""
Bug Bounty & Security Research System — Multi-Agent Framework v7.0.
Enterprise-grade autonomous security research platform with 10 specialized agents.

Built per specification:
- Foundational Principles (Legal & Ethical, QA, Scope Enforcement)
- 10 Agent Subsystems (URL Parser → Policy Enforcer → Scope Guardian → ... → Report Generation)
- Decision Hierarchy (5 levels, absolute priority order)
- Agent-Tool Integration (25+ tools automatically used by agents)
"""

from ..agent_tool_integration import (
    INTEGRATION_PLAN,
    AgentToolIntegration,
    get_agent_tool_integration,
)
from .active_enum import ActiveEnumerationAgent, ActiveEnumResult
from .agent_memory import AgentMemory, MemoryEntry
from .analysis import (
    AnalysisAgent,
    CVSSEntry,
    CVSSMetrics,
    CVSSScore,
    CWEAlternative,
    CWEInfo,
    DetailedAnalysis,
    FindingAnalysis,
    OWASPAlternative,
    OWASPInfo,
)
from .data_sources import (
    CensysClient,
    DataSourceAggregator,
    DataSourceResult,
    SecurityTrailsClient,
    ShodanClient,
    URLScanClient,
)
from .execution_engine import (
    ParallelExecutor,
    RateLimiter,
    ResultCache,
    TimeoutManager,
    get_parallel_executor,
    get_rate_limiter,
    get_result_cache,
    get_timeout_manager,
)
from .exploitation import ExploitationAgent, ProofOfConcept
from .llm_provider import (
    CVSSAssessment,
    LLMAnalysis,
    LLMConfig,
    LLMProvider,
    LLMProviderType,
    VulnerabilityHypothesis,
    get_llm_provider,
)
from .orchestrator import BugBountyOrchestrator, BugBountyPipelineResult
from .passive_intel import (
    AssetClass,
    AssetPriority,
    DiscoveredAsset,
    PassiveIntelligenceAgent,
    PassiveIntelResult,
    ReliabilityLevel,
)
from .policy_enforcer import (
    AssetEligibility,
    DuplicateRisk,
    EvidenceTier,
    PolicyDecision,
    PolicyDecisionOutput,
    PolicyEnforcementResult,
    PolicyEnforcerAgent,
    PolicyRule,
    ScopeStatus,
    TestingCompliance,
    VulnEligibility,
)
from .report_generation import ReportGenerationAgent, VulnerabilityReport
from .scope_guardian import (
    AssetType,
    AuthorizationState,
    OwnershipStatus,
    RiskLevel,
    ScopeAuthorization,
    ScopeCheckResult,
    ScopeGuardianAgent,
)
from .security_guard import (
    EthicalCheckResult,
    EthicalGuard,
    OutputSanitizer,
    ResourceLimiter,
    ResourceLimitResult,
    SanitizationResult,
    ScopeValidationResult,
    ScopeValidator,
    get_ethical_guard,
    get_output_sanitizer,
    get_resource_limiter,
    get_scope_validator,
)
from .system_prompts import (
    AGENT_ARCHITECTURE,
    DECISION_HIERARCHY,
    FOUNDATIONAL_PRINCIPLES,
    get_full_system_prompt,
)
from .url_parser import ProgramIntelligence, URLParserAgent
from .validation_engine import NormalizedFinding, ValidationEngineAgent, ValidationResult
from .vuln_scanner import TestResult, VulnerabilityScannerAgent
from .webhook import (
    WEBHOOK_EVENT_PIPELINE_COMPLETED,
    WEBHOOK_EVENT_POLICY_DECISION,
    WebhookConfig,
    WebhookDelivery,
    WebhookManager,
)

__all__ = [
    "AGENT_ARCHITECTURE",
    "DECISION_HIERARCHY",
    "FOUNDATIONAL_PRINCIPLES",
    "INTEGRATION_PLAN",
    "WEBHOOK_EVENT_PIPELINE_COMPLETED",
    "WEBHOOK_EVENT_POLICY_DECISION",
    "ActiveEnumResult",
    "ActiveEnumerationAgent",
    "AgentMemory",
    "AgentToolIntegration",
    "AnalysisAgent",
    "AssetClass",
    "AssetEligibility",
    "AssetPriority",
    "AssetType",
    "AuthorizationState",
    "BugBountyOrchestrator",
    "BugBountyPipelineResult",
    "CVSSAssessment",
    "CVSSEntry",
    "CVSSMetrics",
    "CVSSScore",
    "CWEAlternative",
    "CWEInfo",
    "CensysClient",
    "DataSourceAggregator",
    "DataSourceResult",
    "DetailedAnalysis",
    "DiscoveredAsset",
    "DuplicateRisk",
    "EthicalCheckResult",
    "EthicalGuard",
    "EvidenceTier",
    "ExploitationAgent",
    "FindingAnalysis",
    "LLMAnalysis",
    "LLMConfig",
    "LLMProvider",
    "LLMProviderType",
    "MemoryEntry",
    "NormalizedFinding",
    "OWASPAlternative",
    "OWASPInfo",
    "OutputSanitizer",
    "OwnershipStatus",
    "ParallelExecutor",
    "PassiveIntelResult",
    "PassiveIntelligenceAgent",
    "PolicyDecision",
    "PolicyDecisionOutput",
    "PolicyEnforcementResult",
    "PolicyEnforcerAgent",
    "PolicyRule",
    "ProgramIntelligence",
    "ProofOfConcept",
    "RateLimiter",
    "ReliabilityLevel",
    "ReportGenerationAgent",
    "ResourceLimitResult",
    "ResourceLimiter",
    "ResultCache",
    "RiskLevel",
    "SanitizationResult",
    "ScopeAuthorization",
    "ScopeCheckResult",
    "ScopeGuardianAgent",
    "ScopeStatus",
    "ScopeValidationResult",
    "ScopeValidator",
    "SecurityTrailsClient",
    "ShodanClient",
    "TestResult",
    "TestingCompliance",
    "TimeoutManager",
    "URLParserAgent",
    "URLScanClient",
    "ValidationEngineAgent",
    "ValidationResult",
    "VulnEligibility",
    "VulnerabilityHypothesis",
    "VulnerabilityReport",
    "VulnerabilityScannerAgent",
    "WebhookConfig",
    "WebhookDelivery",
    "WebhookManager",
    "get_agent_tool_integration",
    "get_ethical_guard",
    "get_full_system_prompt",
    "get_llm_provider",
    "get_output_sanitizer",
    "get_parallel_executor",
    "get_rate_limiter",
    "get_resource_limiter",
    "get_result_cache",
    "get_scope_validator",
    "get_timeout_manager",
]
