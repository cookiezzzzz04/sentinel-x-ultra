"""Configuration management for SENTINEL-X ULTRA."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

from .providers import ModelConfig, ProviderConfig, ProviderType


class ServerConfig(BaseModel):
    """Web server configuration."""
    host: str = "127.0.0.1"
    port: int = 7860
    reload: bool = False
    log_level: str = "INFO"


class StorageConfig(BaseModel):
    """Storage configuration."""
    base_path: Path = Path.home() / ".sentinel-x"
    projects_dir: str = "projects"
    reports_dir: str = "reports"


class Settings(BaseSettings):
    """Main settings class."""
    # Server
    server: ServerConfig = Field(default_factory=ServerConfig)

    # Storage
    storage: StorageConfig = Field(default_factory=StorageConfig)

    # Default LLM Provider
    default_provider: ProviderType = ProviderType.ANTHROPIC
    default_base_url: str = "https://api.anthropic.com"
    default_api_key: str | None = None

    # Model defaults
    models: ModelConfig = Field(default_factory=ModelConfig)

    class Config:
        env_prefix = "SENTINELX_"
        case_sensitive = False

    def get_provider_config(self) -> ProviderConfig:
        """Build the default provider configuration."""
        api_key = self.default_api_key
        if api_key is None:
            # Try to load from environment
            provider_name = self.default_provider.value.upper()
            api_key = os.getenv(f"{provider_name}_API_KEY")

        base_url = os.getenv(f"{self.default_provider.value.upper()}_BASE_URL", self.default_base_url)

        return ProviderConfig(
            provider=self.default_provider,
            base_url=base_url,
            api_key=api_key,
            models=self.models,
        )


def load_settings() -> Settings:
    """Load settings from environment and config files."""
    return Settings()


def get_config_path() -> Path:
    """Get the configuration file path."""
    return Path.home() / ".sentinel-x" / "config.yaml"


def save_default_config():
    """Save default configuration file."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        config_content = """# SENTINEL-X ULTRA Configuration

server:
  host: "127.0.0.1"
  port: 7860
  reload: false
  log_level: "INFO"

storage:
  base_path: "~/.sentinel-x"
  projects_dir: "projects"
  reports_dir: "reports"

# Default LLM Provider
default_provider: "anthropic"  # anthropic | openai | ollama | vllm | gemini | mistral
default_base_url: "https://api.anthropic.com"

# Model Configuration
models:
  reasoning: "claude-sonnet-4-20250514"
  code: "claude-sonnet-4-20250514"
  embedding: "embed-english-v3.0"
  report: "claude-sonnet-4-20250514"

# Environment variables to set:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# OLLAMA_BASE_URL=http://localhost:11434
"""
        config_path.write_text(config_content)
        print(f"Default config saved to {config_path}")
