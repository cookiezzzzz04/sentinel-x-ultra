# SENTINEL-X ULTRA

**Autonomous Security Analysis Intelligence Framework**

Version 0.1.0 — Phase 1 Complete

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Start the server
python -m sentinel_x_ultra start

# Or use the CLI
sentinel-x start
```

Then open http://127.0.0.1:7860 in your browser.

## What Works So Far (Phase 1)

- ✅ Provider Abstraction Layer (Anthropic, OpenAI-compatible, Gemini, Mistral)
- ✅ Multi-Agent Framework (BaseAgent, MessageBus, AgentRegistry)
- ✅ Memory Engine (Project state persistence)
- ✅ RAG Intelligence System (Indexing and Retrieval)
- ✅ FastAPI Web Server with WebSocket support
- ✅ CLI Launcher (`sentinel-x start`)
- ✅ Basic React UI (Dashboard, Model Config)

## Architecture

```
sentinel_x_ultra/
├── providers.py     # Multi-backend LLM abstraction
├── agents.py        # Agent framework + message bus
├── memory.py        # Project state management
├── rag.py           # RAG intelligence system
├── config.py        # Configuration management
├── server.py        # FastAPI web server
├── cli.py           # CLI commands
└── models.py        # Data models
```

## Next Steps (Phase 2+)

- Implement actual agents (ReconAgent, CodeReviewAgent, etc.)
- Build web crawling and vulnerability scanning
- Add the 5-agent Debate Engine
- Full RAG with vector embeddings
- Complete React UI with real-time updates

## Configuration

Edit `~/.sentinel-x/config.yaml` or set environment variables:

```bash
export ANTHROPIC_API_KEY="your-key"
export OLLAMA_BASE_URL="http://localhost:11434"
```

## License

MIT