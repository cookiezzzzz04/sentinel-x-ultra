"""Tests for the V3 additions: workspace, terminal/audit log, and agent knowledge."""

from __future__ import annotations

import json
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

# Make sure the package is importable when tests are run from the repo root.
_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_x_ultra.workspace import (  # noqa: E402
    FileCategory,
    ProjectWorkspaceManager,
    WORKSPACE_DIRS,
    _safe_dir_name,
)
from sentinel_x_ultra.terminal import (  # noqa: E402
    AuditEntry,
    DEFAULT_ALLOWLIST,
    TerminalWorkspace,
)
from sentinel_x_ultra.agent_knowledge import (  # noqa: E402
    AGENT_OWNERSHIP,
    AgentKnowledgeStore,
    KnowledgeKind,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_workspace_root(tmp_path: Path) -> Path:
    return tmp_path


# ---------------------------------------------------------------------------
# Project Workspace System
# ---------------------------------------------------------------------------


class TestProjectWorkspace:
    def test_safe_dir_name_replaces_bad_chars(self):
        assert _safe_dir_name("Acme<Corp>") == "Acme_Corp_"
        assert _safe_dir_name("   ..project..   ") == "project"
        assert _safe_dir_name("ok-name_1") == "ok-name_1"

    def test_create_workspace_creates_all_dirs(self, tmp_workspace_root: Path):
        mgr = ProjectWorkspaceManager(base_path=tmp_workspace_root)
        ws = mgr.create_workspace("proj-1", "Acme Corp")
        for sub in WORKSPACE_DIRS:
            assert (ws.root / sub).is_dir()
        manifest = json.loads((ws.root / "workspace.json").read_text())
        assert manifest["project_id"] == "proj-1"
        assert set(manifest["dirs"]) == set(WORKSPACE_DIRS)

    def test_add_text_file_indexes_with_tags(self, tmp_workspace_root: Path):
        mgr = ProjectWorkspaceManager(base_path=tmp_workspace_root)
        ws = mgr.create_workspace("proj-2", "demo")
        item = mgr.add_text_file(
            "proj-2",
            FileCategory.DOCUMENTATION,
            "scratch.md",
            "## Hello\nnotes here",
            tags=["investigation"],
            agent_owners=["documentation"],
        )
        assert item is not None
        assert item.category == "documentation"
        assert "investigation" in item.tags
        assert "doc" in item.tags  # default tag for DOCUMENTATION
        assert "documentation" in item.agent_owners
        assert (ws.root / "documentation" / "scratch.md").exists()

    def test_add_file_copies_and_categorises(self, tmp_workspace_root: Path):
        mgr = ProjectWorkspaceManager(base_path=tmp_workspace_root)
        mgr.create_workspace("proj-3", "demo")
        # Place the source *outside* the project workspace to prove it's copied in.
        src = tmp_workspace_root / "victim.py"
        src.write_text("print('hi')")
        item = mgr.add_file("proj-3", src)
        assert item is not None
        assert item.category == FileCategory.SOURCE_CODE.value
        # File was actually copied
        ws_root = mgr.get_workspace("proj-3").root
        copied = ws_root / "source-code" / "victim.py"
        assert copied.exists()
        assert copied.read_text() == "print('hi')"

    def test_search_by_agent_owner(self, tmp_workspace_root: Path):
        mgr = ProjectWorkspaceManager(base_path=tmp_workspace_root)
        mgr.create_workspace("proj-4", "demo")
        mgr.add_text_file("proj-4", FileCategory.DOCUMENTATION, "a.md", "x",
                          agent_owners=["documentation"])
        mgr.add_text_file("proj-4", FileCategory.OTHER, "b.md", "y",
                          agent_owners=["tooling"])
        results = mgr.search("proj-4", agent="tooling")
        assert len(results) == 1
        assert results[0].relative_path.endswith("b.md")

    def test_unknown_project_returns_none(self, tmp_workspace_root: Path):
        mgr = ProjectWorkspaceManager(base_path=tmp_workspace_root)
        assert mgr.get_workspace("nope") is None
        assert mgr.add_text_file("nope", FileCategory.NOTE, "x", "x") is None


# ---------------------------------------------------------------------------
# Terminal Workspace + AUDIT_LOG
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTerminalWorkspace:
    async def test_audit_entry_has_required_fields(self):
        entry = AuditEntry(
            timestamp="2025-01-01T00:00:00",
            agent="test",
            command="ls",
            result="ok",
            reason="",
        )
        line = entry.to_log_line()
        assert "agent=test" in line
        assert "result=ok" in line
        assert "ls" in line

    async def test_allowlisted_command_runs_and_logs(self, tmp_path: Path):
        term = TerminalWorkspace(
            tmp_path, allowlist=("ls", "echo"), default_timeout_s=10
        )
        result = await term.execute("ls", agent="test", reason="list dir")
        assert result.success
        assert result.audit.result == "ok"
        assert result.audit.command == "ls"
        assert result.audit.reason == "list dir"
        # Appended to log file
        log_text = term.audit_log_path.read_text()
        assert "ls" in log_text
        assert "agent=test" in log_text

    async def test_rejected_command_logged(self, tmp_path: Path):
        term = TerminalWorkspace(tmp_path, allowlist=("ls",))
        result = await term.execute("rm -rf /", agent="test", reason="")
        assert result.success is False
        assert result.audit.result == "rejected"
        assert "not in the allow-list" in result.audit.reason
        # Entry was recorded
        assert len(term.get_audit_log()) == 1

    async def test_allow_any_bypasses_allowlist(self, tmp_path: Path):
        term = TerminalWorkspace(
            tmp_path, allowlist=("nonexistent",), allow_any=True
        )
        # Use `echo` even though it's not in the (deliberately empty) list
        result = await term.execute("echo hi", agent="t")
        # Either succeeds (echo on PATH) or errors on exec — but should not
        # be rejected for allow-list reasons.
        assert result.audit.result in ("ok", "error")
        assert result.audit.result != "rejected"

    async def test_audit_log_path_created_in_logs_dir(self, tmp_path: Path):
        term = TerminalWorkspace(tmp_path, allowlist=("echo",))
        await term.execute("echo hi", agent="t")
        assert term.audit_log_path.exists()
        assert term.audit_log_path.parent.name == "logs"

    async def test_default_allowlist_includes_common_tools(self):
        for cmd in ("ls", "find", "git", "pytest", "nmap", "semgrep"):
            assert cmd in DEFAULT_ALLOWLIST


# ---------------------------------------------------------------------------
# Agent-Centric Knowledge System
# ---------------------------------------------------------------------------


class TestAgentKnowledgeStore:
    def test_ownership_matches_v3_spec(self):
        # The five canonical V3 agents and their required knowledge kinds
        assert "program_rules" in AGENT_OWNERSHIP["documentation"]
        assert "scope_documents" in AGENT_OWNERSHIP["documentation"]
        assert "tool_references" in AGENT_OWNERSHIP["tooling"]
        assert "report_templates" in AGENT_OWNERSHIP["reporting"]
        assert "data_flow_maps" in AGENT_OWNERSHIP["architecture"]
        assert "user_journeys" in AGENT_OWNERSHIP["business_logic"]

    def test_validate_ownership_rejects_cross_agent_kinds(self):
        assert AgentKnowledgeStore.validate_ownership(
            "documentation", KnowledgeKind.TOOL_REFERENCES
        ) is False
        assert AgentKnowledgeStore.validate_ownership(
            "tooling", KnowledgeKind.TOOL_REFERENCES
        ) is True

    def test_add_persists_to_disk(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        item = store.add(
            "proj-1",
            "documentation",
            KnowledgeKind.PROGRAM_RULES,
            "Rules of engagement",
            body="Be gentle. No DoS.",
            tags=["policy"],
        )
        assert item.item_id
        assert item.title == "Rules of engagement"
        # Reload from disk
        new_store = AgentKnowledgeStore(tmp_path)
        reloaded = new_store.get("proj-1", "documentation", item.item_id)
        assert reloaded is not None
        assert reloaded.body == "Be gentle. No DoS."
        assert "policy" in reloaded.tags

    def test_add_rejects_wrong_ownership(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        with pytest.raises(ValueError):
            store.add(
                "proj-1",
                "documentation",
                KnowledgeKind.TOOL_REFERENCES,  # belongs to tooling
                "Wrong owner",
            )

    def test_list_filters_by_kind(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        store.add("p", "documentation", KnowledgeKind.NOTES, "n1", "b")
        store.add("p", "documentation", KnowledgeKind.NOTES, "n2", "b")
        store.add("p", "documentation", KnowledgeKind.PROGRAM_RULES, "r1", "b")
        notes = store.list("p", "documentation", kind=KnowledgeKind.NOTES)
        assert len(notes) == 2
        assert all(i.kind == KnowledgeKind.NOTES for i in notes)

    def test_update_and_delete(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        item = store.add("p", "tooling", KnowledgeKind.TOOL_REFERENCES, "nmap", "doc")
        updated = store.update("p", "tooling", item.item_id, body="updated body")
        assert updated.body == "updated body"
        # New instance should see the change
        new_store = AgentKnowledgeStore(tmp_path)
        assert new_store.get("p", "tooling", item.item_id).body == "updated body"
        assert new_store.delete("p", "tooling", item.item_id) is True
        assert new_store.get("p", "tooling", item.item_id) is None

    def test_search_finds_across_agents(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        store.add("p", "documentation", KnowledgeKind.NOTES, "nmap usage", "body1")
        store.add("p", "tooling", KnowledgeKind.TOOL_REFERENCES, "nmap tool", "body2")
        results = store.search("p", text="nmap")
        assert len(results) == 2
        agents = {i.agent for i in results}
        assert agents == {"documentation", "tooling"}

    def test_ownership_map_returns_counts(self, tmp_path: Path):
        store = AgentKnowledgeStore(tmp_path)
        store.add("p", "architecture", KnowledgeKind.DATA_FLOW_MAPS, "df", "x")
        om = store.ownership_map("p")
        assert "items=1" in om["architecture"][0]
        assert "items=0" in om["business_logic"][0]
