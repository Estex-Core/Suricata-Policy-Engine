#!/usr/bin/env python3
"""Run history and artifact snapshots for Suricata Policy Engine."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from runtime_paths import default_state_dir


def default_history_dir(output: Path | None = None) -> Path:
    # History is internal state; do not clutter the Suricata rules directory.
    return default_state_dir() / "history"


def _sha(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_copy(src: Path | None, dst: Path) -> dict | None:
    if not src or not src.exists():
        return None
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)
    return {"name": dst.name, "sha256": _sha(dst), "size": dst.stat().st_size}


def record_run(history_dir: Path, *, output: Path, threshold: Path, policy: Path,
               report: Path | None = None, diff: Path | None = None,
               insights: Path | None = None, telemetry: Path | None = None, state: Path | None = None,
               deployed: bool = False, test_passed: bool = False,
               summary: dict | None = None, keep: int = 10) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_id = stamp
    run_dir = history_dir / run_id
    run_dir.mkdir(parents=True)
    artifacts = {}
    for key, src, name in (
        ("rules", output, "suricata-tuned.rules"),
        ("threshold", threshold, "suricata-tuned.threshold.config"),
        ("policy", policy, "tuning-policy.yaml"),
        ("report", report, "report.json"),
        ("diff", diff, "diff.txt"),
        ("insights", insights, "insights.json"),
        ("telemetry", telemetry, "telemetry.json"),
        ("state", state, "state.json"),
    ):
        meta = _safe_copy(src, run_dir / name) if src else None
        if meta:
            artifacts[key] = meta
    manifest = {
        "version": 1,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "deployed": bool(deployed),
        "test_passed": bool(test_passed),
        "summary": summary or {},
        "artifacts": artifacts,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    prune_history(history_dir, keep)
    return run_dir


def list_runs(history_dir: Path) -> list[dict]:
    rows = []
    if not history_dir.exists():
        return rows
    for p in sorted(history_dir.iterdir(), reverse=True):
        mf = p / "manifest.json"
        if not mf.exists():
            continue
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
            data["path"] = str(p)
            rows.append(data)
        except Exception:
            continue
    return rows


def resolve_run(history_dir: Path, selector: str = "latest", deployed_only: bool = False) -> tuple[Path, dict]:
    rows = list_runs(history_dir)
    if deployed_only:
        rows = [r for r in rows if r.get("deployed")]
    if not rows:
        raise FileNotFoundError("No matching historical runs were found")
    if selector in {"latest", "previous"}:
        idx = 0 if selector == "latest" else 1
        if len(rows) <= idx:
            raise FileNotFoundError(f"No {selector} historical run is available")
        row = rows[idx]
    else:
        candidates = [r for r in rows if str(r.get("run_id", "")).startswith(selector)]
        if len(candidates) != 1:
            raise FileNotFoundError(f"Run selector {selector!r} matched {len(candidates)} runs")
        row = candidates[0]
    return Path(row["path"]), row


def prune_history(history_dir: Path, keep: int = 10) -> None:
    if keep <= 0 or not history_dir.exists():
        return
    dirs = [p for p in sorted(history_dir.iterdir(), reverse=True) if (p / "manifest.json").exists()]
    for p in dirs[keep:]:
        shutil.rmtree(p, ignore_errors=True)
