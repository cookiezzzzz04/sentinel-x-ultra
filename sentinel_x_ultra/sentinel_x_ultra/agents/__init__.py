"""Agents module - Multi-agent framework and Phase 3 specialized agents.

This module provides base agent classes and Phase 3 agents.
Uses explicit module loading to avoid circular import issues.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys


def _load_module_by_path(module_name: str, file_path: str):
    """Load a module directly from a file path, bypassing normal import resolution."""
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    return None

# Pre-load base agents module (agents.py file) immediately
_init_dir = os.path.dirname(__file__)
_agents_py_path = os.path.join(os.path.dirname(_init_dir), 'agents.py')
_load_module_by_path('sentinel_x_ultra.agents._base', _agents_py_path)

# Now get the actual class references from the loaded module
_base_module = sys.modules.get('sentinel_x_ultra.agents._base')
if _base_module:
    BaseAgent = getattr(_base_module, 'BaseAgent', None)
    AgentType = getattr(_base_module, 'AgentType', None)
    TaskPayload = getattr(_base_module, 'TaskPayload', None)
    MessageBus = getattr(_base_module, 'MessageBus', None)
    MessageType = getattr(_base_module, 'MessageType', None)
    AgentMessage = getattr(_base_module, 'AgentMessage', None)
else:
    # Fallback to None if loading failed
    BaseAgent = None
    AgentType = None
    TaskPayload = None
    MessageBus = None
    MessageType = None
    AgentMessage = None

# Lazy loading via __getattr__ for any remaining imports
def __getattr__(name: str):
    # Re-check if we have it now (module might have been loaded after we checked)
    base_mod = sys.modules.get('sentinel_x_ultra.agents._base')
    if base_mod and hasattr(base_mod, name):
        return getattr(base_mod, name)

    # Try to load if not yet loaded
    if 'sentinel_x_ultra.agents._base' not in sys.modules:
        _load_module_by_path('sentinel_x_ultra.agents._base', _agents_py_path)
        base_mod = sys.modules.get('sentinel_x_ultra.agents._base')
        if base_mod and hasattr(base_mod, name):
            return getattr(base_mod, name)

    raise AttributeError(f"module 'sentinel_x_ultra.agents' has no attribute '{name}'")

__all__ = [
    "AgentMessage",
    "AgentType",
    "BaseAgent",
    "MessageBus",
    "MessageType",
    "TaskPayload",
]
