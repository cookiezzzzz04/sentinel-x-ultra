"""End-to-end coverage demo.

Walks the full Coverage Tracking Engine workflow against the in-process
FastAPI app via TestClient:

  1. Creates a project.
  2. Uploads a few representative files (auth, API, dependency, docs).
  3. POSTs /coverage/compute to recompute metrics.
  4. GETs /reports/coverage to render the Blank.md report.
  5. Asserts the rendered markdown contains the `## Coverage` footer
     with non-zero Authentication and Dependency percentages.

File basenames intentionally include the coverage hints (e.g. `auth`,
`api`, `requirements.txt`, `package.json`, `architecture.md`) because
the workspace copies files into directories by extension, so only the
basename survives into the coverage engine's path-hint scan.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))


SAMPLE_FILES: dict[str, str] = {
    "auth_login.py":     "def login(user, pw): return check(user, pw)\n",
    "auth_session.py":   "def session(token): return verify(token)\n",
    "auth_token.py":     "def token(uid): return jwt.encode({'uid': uid})\n",
    "api_users.py":      "router.get('/api/users')\nrouter.post('/api/login')\n",
    "api_orders.py":     "router.get('/api/orders')\n",
    "requirements.txt":  "fastapi==0.115.0\nuvicorn==0.32.0\n",
    "package.json":      '{"name": "app", "deps": {"react": "^18"}}\n',
    "README.md":         "# My App\nThis is the documentation.\n",
    "architecture.md":   "# Architecture\nTrust boundaries and data flow.\n",
}


def _client():
    from fastapi.testclient import TestClient
    from sentinel_x_ultra.server import app
    return TestClient(app)


def test_e2e_coverage_demo():
    client = _client()
    project_name = "e2e-coverage-demo"

    r = client.post("/api/projects", json={"name": project_name})
    assert r.status_code == 200, r.text
    project_id = r.json()["project_id"]
    print(f"\n[demo] created project {project_id} ({project_name})")

    r = client.post(f"/api/projects/{project_id}/workspace/init")
    assert r.status_code == 200, r.text
    print("[demo] initialized workspace")

    tmp_dirs: list[str] = []
    try:
        for rel_path, content in SAMPLE_FILES.items():
            tmp_dir = tempfile.mkdtemp(prefix="e2e_cov_")
            tmp_dirs.append(tmp_dir)
            full = Path(tmp_dir) / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content)
            r = client.post(
                f"/api/projects/{project_id}/workspace/upload",
                json={
                    "source_path": str(full),
                    "tags": [f"path:{rel_path}"],
                },
            )
            assert r.status_code == 200, r.text
    finally:
        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)
    print(f"[demo] uploaded {len(SAMPLE_FILES)} files into the workspace")

    r = client.post(f"/api/projects/{project_id}/coverage/compute", json={})
    assert r.status_code == 200, r.text
    report = r.json()["report"]
    overall = r.json()["overall"]
    print(f"[demo] coverage overall = {overall:.1f}%")
    for dim, pct in report["metrics"].items():
        print(f"        {dim:18s} {pct * 100:5.1f}%")
    assert report["metrics"]["authentication"] > 0, "auth coverage should be > 0"
    assert report["metrics"]["api"] > 0, "api coverage should be > 0"

    r = client.get(f"/api/projects/{project_id}/reports/coverage?view=full")
    assert r.status_code == 200, r.text
    body = r.json()
    md = body["markdown"]
    print("\n[demo] ---- report excerpt ----")
    for line in md.splitlines()[:25]:
        print(f"        {line}")
    print("        ...")
    for line in md.splitlines()[-15:]:
        print(f"        {line}")
    print("[demo] ---- end excerpt ----\n")

    assert "## Coverage" in md
    assert "Authentication" in md
    assert "Dependency" in md
    assert "Overall" in md

    r = client.get(f"/api/projects/{project_id}/coverage")
    assert r.status_code == 200
    assert r.json()["overall"] == overall
    print(f"[demo] /coverage endpoint returns overall = {r.json()['overall']:.1f}%")
    print("[demo] OK")
