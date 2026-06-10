"""Methodology Reference Engine — V3.

The V3 spec says:

    Use external methodology repositories as references.
    Knowledge Sources:
      - Bug bounty report templates
      - Security testing workflows
      - Tooling references
      - Research methodologies
      - Reporting structures
    Use them to improve: reporting quality, coverage tracking, workflow
    organization, investigation planning.
    Do not treat them as evidence. Do not treat them as findings.
    Evidence must come from the analyzed target.

This module ships a :class:`MethodologyReferenceEngine` pre-seeded with the
three references mentioned in the V3 spec, and exposes a small API for
agents to query them. References are *not* used as evidence; they only
inform how agents structure, prioritize, and phrase their work.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import structlog

logger = structlog.get_logger()


# ---- Reference data (seeded from V3 spec) ------------------------------------

# ZephrFish/BugBountyTemplates/Blank.md — see https://github.com/ZephrFish/BugBountyTemplates
BLANK_MD_TEMPLATE_SECTIONS: tuple[str, ...] = (
    "Title",
    "Issue Description",
    "Affected URL/Area",
    "Risk Rating",
    "Impact",
    "Attack Scenario",
    "Steps to Reproduce/PoC",
    "Request",
    "Response",
    "Screenshots",
    "Affected Demographic/User Base",
    "Recommended Fix",
    "References",
)


# securitycipher/guide-for-burp-suite — workflow phases derived from the
# tutorial list in that repository.
BURP_SUITE_PHASES: tuple[str, ...] = (
    "Setup & Configuration (FoxyProxy, CA Certificate, Lab)",
    "Information Gathering (Target Tab, Dashboard)",
    "Interception & Modification (Proxy, Repeater)",
    "Automation & Fuzzing (Intruder, Sequencer, Scanner)",
    "Analysis & Comparison (Decoder, Comparer)",
    "Extensibility (Extender, BApps)",
)


# vavkamil/awesome-bugbounty-tools — category taxonomy from the README.
AWESOME_BBB_TOOLS_CATEGORIES: tuple[str, ...] = (
    "Recon — Subdomain Enumeration",
    "Recon — Port Scanning",
    "Recon — Screenshots",
    "Technologies",
    "Content Discovery",
    "Links",
    "Parameters",
    "Fuzzing",
    "Exploitation",
    "Secrets & Git",
    "Web Proxy & Traffic Interception",
    "AI Agents",
)


# Curated tool index — representative entries parsed from the awesome list.
# Full lists are fetched live by agents if needed; this is a fast seed index.
SEED_TOOL_INDEX: tuple[dict[str, str], ...] = (
    {"name": "Sublist3r",       "category": "Recon — Subdomain Enumeration", "url": "https://github.com/aboul3la/Sublist3r"},
    {"name": "Amass",           "category": "Recon — Subdomain Enumeration", "url": "https://github.com/OWASP/Amass"},
    {"name": "subfinder",       "category": "Recon — Subdomain Enumeration", "url": "https://github.com/projectdiscovery/subfinder"},
    {"name": "masscan",         "category": "Recon — Port Scanning",          "url": "https://github.com/robertdavidgraham/masscan"},
    {"name": "nmap",            "category": "Recon — Port Scanning",          "url": "https://github.com/nmap/nmap"},
    {"name": "httpx",           "category": "Technologies",                  "url": "https://github.com/projectdiscovery/httpx"},
    {"name": "wappalyzer",      "category": "Technologies",                  "url": "https://github.com/AliasIO/wappalyzer"},
    {"name": "gobuster",        "category": "Content Discovery",             "url": "https://github.com/OJ/gobuster"},
    {"name": "feroxbuster",     "category": "Content Discovery",             "url": "https://github.com/epi052/feroxbuster"},
    {"name": "ffuf",            "category": "Fuzzing",                       "url": "https://github.com/ffuf/ffuf"},
    {"name": "wfuzz",           "category": "Fuzzing",                       "url": "https://github.com/xmendez/wfuzz"},
    {"name": "sqlmap",          "category": "Exploitation",                  "url": "https://github.com/sqlmapproject/sqlmap"},
    {"name": "Burp Suite",      "category": "Web Proxy & Traffic Interception", "url": "https://portswigger.net/burp"},
    {"name": "mitmproxy",       "category": "Web Proxy & Traffic Interception", "url": "https://github.com/mitmproxy/mitmproxy"},
    {"name": "trufflehog",      "category": "Secrets & Git",                 "url": "https://github.com/trufflesecurity/trufflehog"},
    {"name": "gitleaks",        "category": "Secrets & Git",                 "url": "https://github.com/gitleaks/gitleaks"},
    {"name": "PentestGPT",      "category": "AI Agents",                     "url": "https://github.com/GreyDLAB/PentestGPT"},
    {"name": "katana",          "category": "Content Discovery",             "url": "https://github.com/projectdiscovery/katana"},
    {"name": "waybackurls",     "category": "Links",                         "url": "https://github.com/tomnomnom/waybackurls"},
    {"name": "Arjun",           "category": "Parameters",                    "url": "https://github.com/s0md3v/Arjun"},
)


# ---- Data model ---------------------------------------------------------------

class ReferenceKind(str):
    REPORT_TEMPLATE = "report_template"
    WORKFLOW = "workflow"
    TOOL_INDEX = "tool_index"
    RESEARCH = "research"
    METHODOLOGY = "methodology"
    OTHER = "other"


@dataclass
class MethodologyReference:
    """A single methodology reference (e.g. a GitHub repo or doc)."""

    reference_id: str
    title: str
    kind: str
    url: str
    description: str = ""
    sections: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    indexed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MethodologyReference":
        return cls(**data)


# ---- Engine ------------------------------------------------------------------

class MethodologyReferenceEngine:
    """Indexes external references and serves them to agents.

    References are *not* evidence — they only inform how agents structure
    their work. The :meth:`is_evidence` helper enforces this distinction
    and is called by the Finding Validation Pipeline.
    """

    def __init__(self, store_path: Path | None = None):
        self.store_path = store_path
        self._references: dict[str, MethodologyReference] = {}
        self._tools: dict[str, dict[str, str]] = {}
        self._load_seed()
        if store_path:
            self._load_persisted(store_path)

    # ---- seeding -----------------------------------------------------------

    def _load_seed(self) -> None:
        now = datetime.utcnow().isoformat()
        # Report template (ZephrFish/BugBountyTemplates/Blank.md)
        self.add_reference(
            title="ZephrFish Bug Bounty Report Template (Blank.md)",
            kind=ReferenceKind.REPORT_TEMPLATE,
            url=(
                "https://github.com/ZephrFish/BugBountyTemplates/blob/main/Blank.md"
            ),
            description=(
                "Standardized Markdown template for bug bounty reports. "
                "Defines sections for Title, Issue Description, Affected URL, "
                "Risk Rating, Impact, Attack Scenario, Steps to Reproduce, "
                "Request/Response evidence, Screenshots, Recommended Fix, "
                "and References."
            ),
            sections=list(BLANK_MD_TEMPLATE_SECTIONS),
            tags=["bug-bounty", "report", "markdown", "evidence"],
            indexed_at=now,
        )
        # Burp Suite workflow
        self.add_reference(
            title="SecurityCipher Guide for Burp Suite",
            kind=ReferenceKind.WORKFLOW,
            url="https://github.com/securitycipher/guide-for-burp-suite",
            description=(
                "Comprehensive tutorial list for Burp Suite covering setup, "
                "proxy, repeater, intruder, scanner, and extensions. Provides "
                "the tool-centric methodology for web testing."
            ),
            sections=list(BURP_SUITE_PHASES),
            tags=["burp", "web", "proxy", "workflow", "methodology"],
            indexed_at=now,
        )
        # Tools list
        self.add_reference(
            title="Awesome Bug Bounty Tools (vavkamil)",
            kind=ReferenceKind.TOOL_INDEX,
            url="https://github.com/vavkamil/awesome-bugbounty-tools",
            description=(
                "Curated, categorized list of bug-bounty / pentesting tools. "
                "Categories include Recon, Technologies, Content Discovery, "
                "Links, Parameters, Fuzzing, Exploitation, Secrets & Git, "
                "Web Proxy, and AI Agents."
            ),
            sections=list(AWESOME_BBB_TOOLS_CATEGORIES),
            tags=["awesome-list", "tools", "recon", "fuzzing", "exploitation"],
            indexed_at=now,
        )
        # Seed tool index entries attached to the tool_index reference
        for entry in SEED_TOOL_INDEX:
            self._index_tool(
                entry["name"],
                entry["category"],
                entry["url"],
                source_ref=self._references[
                    next(iter(self._references))
                ].reference_id,
            )

    def _load_persisted(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for raw in data.get("references", []):
                ref = MethodologyReference.from_dict(raw)
                self._references[ref.reference_id] = ref
        except Exception as e:  # pragma: no cover - defensive
            logger.error("methodology_load_failed", path=str(path), error=str(e))

    def _persist(self) -> None:
        if not self.store_path:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(
            json.dumps(
                {
                    "references": [r.to_dict() for r in self._references.values()],
                    "tools": list(self._tools.values()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # ---- CRUD --------------------------------------------------------------

    def add_reference(
        self,
        title: str,
        kind: str,
        url: str,
        *,
        description: str = "",
        sections: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        indexed_at: str | None = None,
    ) -> MethodologyReference:
        ref = MethodologyReference(
            reference_id=str(uuid.uuid4()),
            title=title,
            kind=kind,
            url=url,
            description=description,
            sections=list(sections or []),
            tags=list(tags or []),
            indexed_at=indexed_at or datetime.utcnow().isoformat(),
        )
        self._references[ref.reference_id] = ref
        self._persist()
        return ref

    # ---- Tool index --------------------------------------------------------

    def _index_tool(
        self, name: str, category: str, url: str, *, source_ref: str
    ) -> None:
        self._tools[name.lower()] = {
            "name": name,
            "category": category,
            "url": url,
            "source_ref": source_ref,
        }

    def _ensure_tools(self) -> None:
        if not getattr(self, "_tools", None):
            self._tools = {}
            for entry in SEED_TOOL_INDEX:
                self._index_tool(
                    entry["name"],
                    entry["category"],
                    entry["url"],
                    source_ref="seed",
                )

    # ---- queries -----------------------------------------------------------

    def list_references(
        self, *, kind: str | None = None, tag: str | None = None
    ) -> list[MethodologyReference]:
        out: list[MethodologyReference] = []
        for r in self._references.values():
            if kind and r.kind != kind:
                continue
            if tag and tag not in r.tags:
                continue
            out.append(r)
        return out

    def get_reference(self, reference_id: str) -> MethodologyReference | None:
        return self._references.get(reference_id)

    def categories(self) -> list[str]:
        cats: set[str] = set()
        for r in self._references.values():
            cats.update(r.sections)
        return sorted(cats)

    def tools_by_category(self, category: str) -> list[dict[str, str]]:
        self._ensure_tools()
        return [
            t for t in self._tools.values() if t["category"].lower() == category.lower()
        ]

    def all_tools(self) -> list[dict[str, str]]:
        self._ensure_tools()
        return list(self._tools.values())

    def get_report_template_sections(self) -> list[str]:
        """Convenience: return the Blank.md section list."""
        return list(BLANK_MD_TEMPLATE_SECTIONS)

    def get_burp_suite_phases(self) -> list[str]:
        return list(BURP_SUITE_PHASES)

    # ---- evidence rule (Golden Rule) --------------------------------------

    @staticmethod
    def is_evidence(source: str) -> bool:
        """A reference is *never* evidence. Evidence comes from the target.

        The Finding Validation Pipeline calls this to enforce the
        Golden Rule: a finding's evidence must NOT be a methodology
        reference.
        """
        source_l = (source or "").lower()
        if not source_l:
            return False
        if "github.com/" in source_l or "://" in source_l and "methodology" in source_l:
            # Allow tools/repos as references, but reject them when used
            # as the *only* evidence for a finding.
            return False
        return True


# Module-level singleton (created lazily so tests can inject their own).
_engine: MethodologyReferenceEngine | None = None


def get_methodology_engine(
    store_path: Path | None = None,
) -> MethodologyReferenceEngine:
    global _engine
    if _engine is None:
        _engine = MethodologyReferenceEngine(store_path=store_path)
    return _engine
