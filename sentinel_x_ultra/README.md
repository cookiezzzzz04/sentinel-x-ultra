# SENTINEL-X ULTRA — Bug Bounty & Security Analysis Framework

**This is the Python package directory.**

For full documentation — install guide, API reference, agent descriptions, and architecture — see the **[root README](../README.md)**.

---

## Quick Start

```bash
cd sentinel_x_ultra
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

Then open **http://127.0.0.1:7860**.

---

## Run Tests

```bash
cd sentinel_x_ultra
python -m pytest sentinel_x_ultra/tests/test_bug_bounty.py -v
```

---

## Package Contents

| Path | Description |
|------|-------------|
| `server.py` | FastAPI web server |
| `config.py` | Settings & configuration |
| `bug_bounty/` | 10-agent bug bounty pipeline |
| `agents/` | Phase 3-5 AI agents |
| `analyzers/` | SAST & web analysis engines |
| `engines/` | Knowledge graph, permission graph, business rules |
| `tests/` | Test suite (22 tests) |

For details on each module, see the [root README](../README.md).
