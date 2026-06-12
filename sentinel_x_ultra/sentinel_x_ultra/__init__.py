"""SENTINEL-X ULTRA - Autonomous Security Analysis Intelligence Framework"""

__version__ = "0.1.0"

# ============================================================================
# Tools Registry - all tools are accessible via their module getter functions
# ============================================================================

from .recon_tools import (
    ReconResult,
    ReconnaissanceWorkflow,
    SubFinderTool,
    SubEnumTool,
    WaybackUrlsTool,
    GauTool,
    HttpxTool,
    DalfoxTool,
    SqlifinderTool,
    NucleiTool,
    SENTINELX_TOOLS_DIR,
    get_recon_workflow,
)

from .nmap_tool import NmapTool, NmapResult, get_nmap_tool
from .ffuf_tool import FfufTool, FfufResult, get_ffuf_tool
from .gobuster_tool import GobusterTool, GobusterResult, get_gobuster_tool
from .hydra_tool import HydraTool, HydraResult, get_hydra_tool
from .sqlmap_tool import SQLMapTool, SQLMapResult, get_sqlmap_tool
from .xxe_tool import XXETool, XXEResult, get_xxe_tool
from .deserialization_tool import DeserializationTool, DeserializationResult, get_deserialization_tool

# ============================================================================
# Collective tool registry
# ============================================================================

TOOL_REGISTRY = {
    # Core tools
    "nmap": ("nmap_tool", "get_nmap_tool", "NmapTool"),
    "ffuf": ("ffuf_tool", "get_ffuf_tool", "FfufTool"),
    "gobuster": ("gobuster_tool", "get_gobuster_tool", "GobusterTool"),
    "hydra": ("hydra_tool", "get_hydra_tool", "HydraTool"),
    "sqlmap": ("sqlmap_tool", "get_sqlmap_tool", "SQLMapTool"),
    "xxe": ("xxe_tool", "get_xxe_tool", "XXETool"),
    "deserialization": ("deserialization_tool", "get_deserialization_tool", "DeserializationTool"),
    # Extended tools (recon_tools_extended.py)
    "amass": ("recon_tools_extended", "get_amass_tool", "AmassTool"),
    "sublist3r": ("recon_tools_extended", "get_sublist3r_tool", "Sublist3rTool"),
    "knockpy": ("recon_tools_extended", "get_knockpy_tool", "KnockpyTool"),
    "dnscan": ("recon_tools_extended", "get_dnscan_tool", "DnscanTool"),
    "massdns": ("recon_tools_extended", "get_massdns_tool", "MassdnsTool"),
    "dnsx": ("recon_tools_extended", "get_dnsx_tool", "DnsxTool"),
    "dirsearch": ("recon_tools_extended", "get_dirsearch_tool", "DirsearchTool"),
    "wfuzz": ("recon_tools_extended", "get_wfuzz_tool", "WfuzzTool"),
    "eyewitness": ("recon_tools_extended", "get_eyewitness_tool", "EyewitnessTool"),
    "gittools": ("recon_tools_extended", "get_gittools_tool", "GitToolsTool"),
    "git_secrets": ("recon_tools_extended", "get_git_secrets_tool", "GitSecretsTool"),
    "retirejs": ("recon_tools_extended", "get_retirejs_tool", "RetireJsTool"),
    "mobsf": ("recon_tools_extended", "get_mobsf_tool", "MobsfTool"),
    "apktool": ("recon_tools_extended", "get_apktool_tool", "ApktoolTool"),
    "wpscan": ("recon_tools_extended", "get_wpscan_tool", "WpscanTool"),
    "cmsmap": ("recon_tools_extended", "get_cmsmap_tool", "CmsmapTool"),
    "corstest": ("recon_tools_extended", "get_corstest_tool", "CorsTestTool"),
    "jwt_toolkit": ("recon_tools_extended", "get_jwt_toolkit_tool", "JwtToolkitTool"),
    "tko_subs": ("recon_tools_extended", "get_tko_subs_tool", "TkoSubsTool"),
}

# Agent-Tool Integration Bridge
from .agent_tool_integration import AgentToolIntegration, get_agent_tool_integration
from .agent_tool_integration import INTEGRATION_PLAN


def get_all_tool_status() -> dict:
    """Get availability status for all registered tools."""
    status = {}
    for name, (module, getter, class_name) in TOOL_REGISTRY.items():
        try:
            import importlib
            mod = importlib.import_module(f".{module}", __package__)
            tool = getattr(mod, getter)()
            status[name] = {
                "available": tool.is_available(),
                "version": tool.get_version() if hasattr(tool, "get_version") else "unknown",
                "name": tool.name if hasattr(tool, "name") else name,
            }
        except Exception as e:
            status[name] = {"available": False, "error": str(e)}
    return status