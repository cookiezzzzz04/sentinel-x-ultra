"""Provider Abstraction Layer - Support for multiple LLM backends."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Literal
from dataclasses import dataclass, field
from enum import Enum

import httpx
from pydantic import BaseModel, Field


class ProviderType(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    VLLM = "vllm"
    GEMINI = "gemini"
    MISTRAL = "mistral"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    OPENCODE = "opencode"
    LOCAL = "local"


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass
class LLMMessage:
    role: MessageRole
    content: str
    name: str | None = None


@dataclass
class ModelConfig:
    reasoning: str = "claude-sonnet-4-20250514"
    code: str = "claude-sonnet-4-20250514"
    embedding: str = "embed-english-v3.0"
    report: str = "claude-sonnet-4-20250514"
    rerank: str | None = None


@dataclass
class ProviderConfig:
    provider: ProviderType
    base_url: str | None = None
    api_key: str | None = None
    models: ModelConfig = field(default_factory=ModelConfig)
    timeout: float = 120.0
    max_retries: int = 3


class LLMResponse(BaseModel):
    content: str
    model: str
    provider: ProviderType
    usage: dict[str, int] | None = None
    latency_ms: float | None = None


class BaseLLMProvider(ABC):
    """Base class for all LLM providers."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            base_url=config.base_url or "",
            timeout=config.timeout,
            headers=self._build_headers(),
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a completion request to the LLM."""
        pass

    @abstractmethod
    async def stream(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Stream completion responses."""
        pass

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    def _extract_usage(self, response_data: dict[str, Any]) -> dict[str, int] | None:
        """Extract token usage from provider response.
        
        Only extracts standard token fields to avoid type mismatches
        when providers return additional timing metrics as floats.
        """
        if "usage" in response_data:
            usage = response_data["usage"]
            return {
                "prompt_tokens": int(usage.get("prompt_tokens", 0)),
                "completion_tokens": int(usage.get("completion_tokens", 0)),
                "total_tokens": int(usage.get("total_tokens", 0)),
            }
        return None


class AnthropicProvider(BaseLLMProvider):
    """Anthropic (Claude) provider."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "https://api.anthropic.com"
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens or 4096,
        }

        # Add system message as first message
        system_messages = [m for m in messages if m.role == MessageRole.SYSTEM]
        if system_messages:
            payload["system"] = system_messages[0].content

        response = await self.client.post("/v1/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["content"][0]["text"],
            model=model,
            provider=ProviderType.ANTHROPIC,
            usage={"input_tokens": data.get("usage", {}).get("input_tokens", 0),
                   "output_tokens": data.get("usage", {}).get("output_tokens", 0)},
            latency_ms=latency,
        )

    async def stream(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens or 4096,
            "stream": True,
        }

        system_messages = [m for m in messages if m.role == MessageRole.SYSTEM]
        if system_messages:
            payload["system"] = system_messages[0].content

        async with self.client.stream("POST", "/v1/messages", json=payload) as response:
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    if line == "data: [DONE]":
                        break
                    import json
                    chunk = json.loads(line[6:])
                    if chunk.get("type") == "content_block_delta":
                        if chunk.get("delta", {}).get("type") == "text_delta":
                            yield chunk["delta"]["text"]


class OpenAICompatibleProvider(BaseLLMProvider):
    """OpenAI-compatible provider (Ollama, LM Studio, vLLM, etc.)."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        response = await self.client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data["model"],
            provider=self._detect_provider(),
            usage=data.get("usage"),
            latency_ms=latency,
        )

    async def stream(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
            "stream": True,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        async with self.client.stream("POST", "/v1/chat/completions", json=payload) as response:
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    if line == "data: [DONE]":
                        break
                    import json
                    chunk = json.loads(line[6:])
                    if chunk.get("choices", [{}])[0].get("delta", {}).get("content"):
                        yield chunk["choices"][0]["delta"]["content"]

    def _detect_provider(self) -> ProviderType:
        url = self.config.base_url or ""
        if "ollama" in url:
            return ProviderType.OLLAMA
        elif "lmstudio" in url:
            return ProviderType.LMSTUDIO
        elif "vllm" in url:
            return ProviderType.VLLM
        return ProviderType.OPENAI


class GeminiProvider(BaseLLMProvider):
    """Google Gemini provider."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "https://generativelanguage.googleapis.com"
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        # Convert messages to Gemini format
        contents = []
        for m in messages:
            if m.role == MessageRole.USER:
                contents.append({"role": "user", "parts": [{"text": m.content}]})
            elif m.role == MessageRole.ASSISTANT:
                contents.append({"role": "model", "parts": [{"text": m.content}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens or 4096,
            },
        }

        api_suffix = f"{self.config.api_key}/v1beta/models/{model}:generateContent"
        response = await self.client.post(api_suffix, json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["candidates"][0]["content"]["parts"][0]["text"],
            model=model,
            provider=ProviderType.GEMINI,
            latency_ms=latency,
        )

    async def stream(self, messages, model, temperature=0.7, max_tokens=None):
        # Streaming implementation for Gemini
        raise NotImplementedError("Gemini streaming not yet implemented")


class MistralProvider(BaseLLMProvider):
    """Mistral AI provider."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "https://api.mistral.ai"
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        response = await self.client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data["model"],
            provider=ProviderType.MISTRAL,
            usage=data.get("usage"),
            latency_ms=latency,
        )

    async def stream(self, messages, model, temperature=0.7, max_tokens=None):
        raise NotImplementedError("Mistral streaming not yet implemented")


class GroqProvider(BaseLLMProvider):
    """Groq provider - fast inference for open models."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "https://api.groq.com"
        super().__init__(config)
        # Groq uses OpenAI-compatible endpoint at /openai/v1/chat/completions
        self.client.headers["Authorization"] = f"Bearer {config.api_key}"

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        # Use a default model if none provided (Groq requires a valid model)
        if not model or model == "claude-sonnet-4-20250514":
            model = "llama-3.1-8b-instant"  # Groq's fastest free model

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        response = await self.client.post("/openai/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data["model"],
            provider=ProviderType.GROQ,
            usage=data.get("usage"),
            latency_ms=latency,
        )

    async def stream(self, messages, model, temperature=0.7, max_tokens=None):
        raise NotImplementedError("Groq streaming not yet implemented")


class OpenRouterProvider(BaseLLMProvider):
    """OpenRouter provider - access to 100+ LLMs through a unified API."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "https://openrouter.ai/api/v1"
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        response = await self.client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data["model"],
            provider=ProviderType.OPENROUTER,
            usage=data.get("usage"),
            latency_ms=latency,
        )

    async def stream(self, messages, model, temperature=0.7, max_tokens=None):
        raise NotImplementedError("OpenRouter streaming not yet implemented")


class OpenCodeProvider(BaseLLMProvider):
    """OpenCode provider - self-hosted code assistant."""

    def __init__(self, config: ProviderConfig):
        if not config.base_url:
            config.base_url = "http://localhost:8080"
        super().__init__(config)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        start = time.perf_counter()

        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        response = await self.client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.perf_counter() - start) * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", "opencode"),
            provider=ProviderType.OPENCODE,
            usage=data.get("usage"),
            latency_ms=latency,
        )

    async def stream(self, messages, model, temperature=0.7, max_tokens=None):
        raise NotImplementedError("OpenCode streaming not yet implemented")


class ProviderRegistry:
    """Registry for LLM providers."""

    def __init__(self):
        self._providers: dict[ProviderType, BaseLLMProvider] = {}

    def register(self, provider_type: ProviderType, provider: BaseLLMProvider):
        self._providers[provider_type] = provider

    def get(self, provider_type: ProviderType) -> BaseLLMProvider | None:
        return self._providers.get(provider_type)

    @staticmethod
    def create_from_config(config: ProviderConfig) -> BaseLLMProvider:
        """Factory method to create provider from config."""
        if config.provider == ProviderType.ANTHROPIC:
            return AnthropicProvider(config)
        elif config.provider == ProviderType.GEMINI:
            return GeminiProvider(config)
        elif config.provider == ProviderType.MISTRAL:
            return MistralProvider(config)
        elif config.provider == ProviderType.GROQ:
            return GroqProvider(config)
        elif config.provider == ProviderType.OPENROUTER:
            return OpenRouterProvider(config)
        elif config.provider == ProviderType.OPENCODE:
            return OpenCodeProvider(config)
        else:
            return OpenAICompatibleProvider(config)


class MultiProviderRouter:
    """Route requests to appropriate providers based on task type."""

    def __init__(self, registry: ProviderRegistry, default_config: ProviderConfig):
        self.registry = registry
        self.default_config = default_config
        self._default_provider: BaseLLMProvider | None = None

    async def initialize(self):
        """Initialize all configured providers."""
        for provider_type in ProviderType:
            config = self._get_config_for_provider(provider_type)
            if config:
                provider = ProviderRegistry.create_from_config(config)
                self.registry.register(provider_type, provider)

        # Create default provider
        self._default_provider = ProviderRegistry.create_from_config(self.default_config)
        self.registry.register(self.default_config.provider, self._default_provider)

    def _get_config_for_provider(self, provider_type: ProviderType) -> ProviderConfig | None:
        # Load from environment or config file
        env_prefix = provider_type.value.upper()
        api_key = os.getenv(f"{env_prefix}_API_KEY")

        base_url = os.getenv(f"{env_prefix}_BASE_URL")

        if api_key or base_url:
            return ProviderConfig(
                provider=provider_type,
                api_key=api_key,
                base_url=base_url,
            )
        return None

    async def complete(
        self,
        messages: list[LLMMessage],
        task_type: Literal["reasoning", "code", "report", "embedding"] = "reasoning",
        provider_type: ProviderType | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Route completion request to appropriate provider."""
        if provider_type is None:
            provider_type = self.default_config.provider

        provider = self.registry.get(provider_type)
        if provider is None:
            provider = self._default_provider

        if provider is None:
            raise RuntimeError("No LLM provider configured")

        # Select model based on task type
        model = self._select_model(task_type, provider_type)

        return await provider.complete(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def _select_model(self, task_type: str, provider_type: ProviderType) -> str:
        """Select appropriate model for task type."""
        models = self.default_config.models

        if task_type == "reasoning":
            return models.reasoning
        elif task_type == "code":
            return models.code
        elif task_type == "report":
            return models.report
        elif task_type == "embedding":
            return models.embedding
        return models.reasoning

    async def close(self):
        """Close all provider clients."""
        for provider in self.registry._providers.values():
            await provider.close()
        if self._default_provider:
            await self._default_provider.close()