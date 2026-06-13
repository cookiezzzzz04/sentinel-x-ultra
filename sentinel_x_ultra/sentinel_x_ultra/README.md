# SENTINEL-X ULTRA — Bug Bounty & Security Analysis Framework

**This is the Python package directory** — where all the backend code lives.

For the full guide — quick start, all commands, where to find things — see the **[root README](../README.md)** instead. This file is just a quick reference for when you're inside this directory.

---

## Quick Start

```bash
# From the sentinel_x_ultra/ directory (one level up from here):
cd ..
uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

Or use the Makefile from the project root.

## Run Tests

```bash
python -m pytest sentinel_x_ultra/tests/ -v
```

## Package Contents

| Path | Description |
|------|-------------|
| `server.py` | FastAPI web server (141+ endpoints) |
| `config.py` | Settings & configuration |
| `cli.py` | Command-line interface |
| `bug_bounty/` | 10-agent bug bounty pipeline |
| `agents/` | Phase 3-5 AI agents (recon, code review, threat modeling) |
| `analyzers/` | SAST & web analysis engines |
| `engines/` | Knowledge graph, permission graph, business rules |
| `tests/` | Test suite (115+ tests) |
