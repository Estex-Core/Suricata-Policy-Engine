#!/usr/bin/env python3
"""Friendly Suricata rules tuner.

Typical workflow:
    sudo suricata-update
    sudo python3 tune_rules.py --test

First production deployment:
    sudo python3 tune_rules.py --deploy

Defaults:
    input rules       : /var/lib/suricata/rules/suricata.rules
    policy            : tuning-policy.yaml beside this script
    tuned rules       : /var/lib/suricata/rules/suricata-tuned.rules
    visible outputs   : suricata-tuned.rules + suricata-tuned.diff.txt
    internal state    : private XDG state directory
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from runtime_paths import default_policy_path, default_baseline_path, default_state_dir
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    import generate_suricata_policy as core
    import policy_insights as insights
    import run_history as history
    import telemetry as telemetry_mod
except Exception as exc:
    raise SystemExit(
        "ERROR: Could not load generate_suricata_policy.py.\n"
        "Keep tune_rules.py and generate_suricata_policy.py in the same directory.\n"
        f"Details: {exc}"
    ) from exc

DEFAULT_RULES = Path("/var/lib/suricata/rules/suricata.rules")
DEFAULT_POLICY = default_policy_path(SCRIPT_DIR)
DEFAULT_SURICATA_CONF = Path("/etc/suricata/suricata.yaml")
GID_RE = re.compile(r"\bgid\s*:\s*(\d+)\s*;", re.I)
MANAGED_BEGIN = "# BEGIN SURICATA FRIENDLY TUNER MANAGED"
MANAGED_END = "# END SURICATA FRIENDLY TUNER MANAGED"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tune_rules.py",
        description="Apply tuning-policy.yaml directly to a fresh Suricata ruleset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                   help="Fresh rules file created by suricata-update")
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY,
                   help="Tuning policy YAML")
    p.add_argument("--output", type=Path, default=None,
                   help="Tuned .rules output (default: suricata-tuned.rules beside input)")
    p.add_argument("--report", type=Path, default=None,
                   help="Optional internal JSON report path (default: private application state directory)")
    p.add_argument("--threshold-output", type=Path, default=None,
                   help="Optional generated threshold/suppress staging path (default: private application state directory)")
    p.add_argument("--state-file", type=Path, default=None,
                   help="Optional previous-run comparison state path (default: private application state directory)")
    p.add_argument("--diff-output", type=Path, default=None,
                   help="Human-readable diff report")
    p.add_argument("--test", action="store_true",
                   help="Run Suricata validation against tuned rules + generated thresholds")
    p.add_argument("--deploy", action="store_true",
                   help="Validate, point suricata.yaml to tuned rules, merge thresholds, and reload rules")
    p.add_argument("--replace-original", action="store_true",
                   help="NOT RECOMMENDED: validate, back up, then replace the original suricata.rules with tuned rules and reload")
    p.add_argument("--no-reload", action="store_true",
                   help="With --deploy/--replace-original, change production files but do not reload/restart the running service")
    p.add_argument("--suricata-conf", type=Path, default=DEFAULT_SURICATA_CONF,
                   help="suricata.yaml used by --test/--deploy")
    p.add_argument("--dry-run", action="store_true",
                   help="Calculate decisions and print summary without writing files")
    p.add_argument("--tracked-baseline", type=Path, default=default_baseline_path(SCRIPT_DIR),
                   help="Pinned fingerprint baseline for tracked SID exceptions")
    p.add_argument("--accept-tracked-baseline", action="store_true",
                   help="Replace tracked SID baseline with fingerprints from the current feed after review")
    p.add_argument("--preview", action="store_true",
                   help="Preview policy health, recommendations, and update impact without writing/deploying rules")
    p.add_argument("--no-state-update", action="store_true",
                   help="Do not replace the previous-run comparison state (useful for pre-deploy --test)")
    p.add_argument("--insights-output", type=Path, default=None,
                   help="Optional JSON output for recommendations, policy health, and update impact")
    p.add_argument("--eve", action="append", type=Path, default=[], metavar="EVE_JSON",
                   help="Read EVE JSON/JSON.GZ telemetry (repeatable); recommendations only, never auto-suppresses")
    p.add_argument("--telemetry-output", type=Path, default=None,
                   help="Telemetry analysis JSON path (default: private application state directory)")
    p.add_argument("--history-dir", type=Path, default=None,
                   help="Run-history directory (default: private application state directory)")
    p.add_argument("--history-limit", type=int, default=5,
                   help="Maximum historical artifact snapshots to keep")
    p.add_argument("--history-list", action="store_true",
                   help="List historical tuner runs and exit")
    p.add_argument("--rollback", nargs="?", const="latest", default=None, metavar="RUN_ID",
                   help="Rollback production to a historical run (default selector: latest)")
    p.add_argument("--no-lock", action="store_true",
                   help="Disable process lock (intended only for isolated tests)")
    return p.parse_args()



_LOCK_FH = None

def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Crash-resistant same-filesystem replace, preserving mode/owner when possible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    stat = None
    try:
        stat = path.stat()
    except FileNotFoundError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if stat is not None:
            os.chmod(tmp, stat.st_mode)
            if os.geteuid() == 0:
                try:
                    os.chown(tmp, stat.st_uid, stat.st_gid)
                except OSError:
                    pass
        os.replace(tmp, path)
        try:
            dfd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def atomic_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.", suffix=".tmp", dir=str(dst.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


def acquire_process_lock(lock_path: Path) -> None:
    global _LOCK_FH
    if _LOCK_FH is not None:
        return
    try:
        import fcntl
    except ImportError:
        return
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        fh.close()
        raise RuntimeError(f"Another tuner process holds lock: {lock_path}") from exc
    fh.seek(0); fh.truncate(); fh.write(f"pid={os.getpid()}\n"); fh.flush()
    _LOCK_FH = fh
    def _release():
        global _LOCK_FH
        if _LOCK_FH is None:
            return
        try:
            fcntl.flock(_LOCK_FH.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            _LOCK_FH.close()
        except Exception:
            pass
        _LOCK_FH = None
    atexit.register(_release)


def reload_suricata(expected_rules: Optional[Path] = None, expected_config: Optional[Path] = None) -> int:
    """Reload/restart Suricata and distinguish LIVE from merely STAGED config.

    A successful blocking socket reload is preferred.  If socket control is not
    available but the systemd service is active, restart it.  A stopped service
    is not called "live"; the config is left staged for the next start.
    """
    sc = shutil.which("suricatasc")
    if sc:
        print("[DEPLOY] Requesting blocking rule reload with suricatasc...")
        proc = subprocess.run([sc, "-c", "reload-rules"], capture_output=True, text=True)
        _print_child_output(proc)
        if proc.returncode == 0:
            if expected_rules is not None:
                conf = subprocess.run([sc, "-c", "conf-get rule-files"], capture_output=True, text=True)
                if conf.returncode == 0:
                    runtime_text = (conf.stdout or "") + "\n" + (conf.stderr or "")
                    if expected_rules.name not in runtime_text and str(expected_rules) not in runtime_text:
                        print(
                            f"[DEPLOY] ERROR: live Suricata rule-files does not report {expected_rules.name} after reload.",
                            file=sys.stderr,
                        )
                        _print_child_output(conf)
                        return 6
            stats = subprocess.run([sc, "-c", "ruleset-stats"], capture_output=True, text=True)
            if stats.returncode == 0:
                _print_child_output(stats)
            print("[DEPLOY] LIVE: blocking Suricata ruleset reload completed.")
            return 0

    systemctl = shutil.which("systemctl")
    service_active = False
    if systemctl:
        service_active = subprocess.run([systemctl, "is-active", "--quiet", "suricata"]).returncode == 0
        if service_active:
            print("[DEPLOY] Socket reload unavailable/failed; restarting active suricata.service...")
            rc = subprocess.run([systemctl, "restart", "suricata"]).returncode
            active_after = subprocess.run([systemctl, "is-active", "--quiet", "suricata"]).returncode == 0
            if rc == 0 and active_after:
                if expected_rules is not None:
                    conflicts = [raw for raw in running_suricata_sigfile_overrides() if not _same_rule_target(raw, expected_rules)]
                    if conflicts:
                        print("[DEPLOY] ERROR: restarted Suricata is pinned to a different -S/--sig-file target.", file=sys.stderr)
                        for raw in conflicts:
                            print(f"         runtime signature override: {raw}", file=sys.stderr)
                        return 9
                if expected_config is not None:
                    runtime_cfgs = running_suricata_config_paths()
                    conflicts = [raw for raw in runtime_cfgs if not _same_config_target(raw, expected_config)]
                    if conflicts:
                        print("[DEPLOY] ERROR: restarted Suricata is using a different configuration file.", file=sys.stderr)
                        for raw in conflicts:
                            print(f"         runtime config: {raw}", file=sys.stderr)
                        return 10
                print("[DEPLOY] LIVE: suricata.service restarted successfully with the verified configuration.")
                return 0
            return rc or 7

    # If a Suricata process exists but neither socket reload nor systemd restart
    # can control it, do not claim activation.
    if _running_suricata_cmdlines():
        print(
            "[DEPLOY] ERROR: a Suricata process is running, but it could not be safely reloaded/restarted.",
            file=sys.stderr,
        )
        return 8

    print("[DEPLOY] STAGED: configuration points to tuned rules, but no running Suricata instance was found.")
    return 0


def rollback_history_run(output: Path, threshold_output: Path, config: Path, history_dir: Path, selector: str, no_reload: bool) -> int:
    if os.geteuid() != 0:
        print("[ROLLBACK] FAILED: rollback must be run as root/sudo.", file=sys.stderr)
        return 30
    try:
        run_dir, manifest = history.resolve_run(history_dir, selector)
    except Exception as exc:
        print(f"[ROLLBACK] FAILED: {exc}", file=sys.stderr)
        return 31
    if not config.exists():
        print(f"[ROLLBACK] FAILED: config not found: {config}", file=sys.stderr)
        return 34
    src_rules = run_dir / "suricata-tuned.rules"
    src_threshold = run_dir / "suricata-tuned.threshold.config"
    if not src_rules.exists() or not src_threshold.exists():
        print("[ROLLBACK] FAILED: selected history snapshot lacks rules/threshold artifacts.", file=sys.stderr)
        return 32
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    rescue = history_dir / ".rollback-backups" / stamp
    rescue.mkdir(parents=True, exist_ok=True)
    threshold_target = resolve_threshold_file(config)
    current_output_exists = output.exists()
    current_threshold_output_exists = threshold_output.exists()
    current_target_exists = threshold_target.exists()
    try:
        if current_output_exists: shutil.copy2(output, rescue / output.name)
        if current_threshold_output_exists: shutil.copy2(threshold_output, rescue / threshold_output.name)
        if config.exists(): shutil.copy2(config, rescue / config.name)
        if current_target_exists: shutil.copy2(threshold_target, rescue / ("production-" + threshold_target.name))
        atomic_copy(src_rules, output)
        atomic_copy(src_threshold, threshold_output)
        patch_rule_files(config, output)
        merge_managed_threshold(threshold_target, threshold_output)
        rc = run_suricata_test(output, threshold_output, config, production=True)
        if rc != 0:
            raise RuntimeError("restored snapshot failed Suricata validation")
        if not no_reload and reload_suricata() != 0:
            raise RuntimeError("Suricata reload/restart failed")
        print(f"[ROLLBACK] PASS: restored run {manifest.get('run_id')} from {run_dir}")
        return 0
    except Exception as exc:
        print(f"[ROLLBACK] ERROR: {exc}; restoring pre-rollback files...", file=sys.stderr)
        if (rescue / output.name).exists(): atomic_copy(rescue / output.name, output)
        elif not current_output_exists: output.unlink(missing_ok=True)
        if (rescue / threshold_output.name).exists(): atomic_copy(rescue / threshold_output.name, threshold_output)
        elif not current_threshold_output_exists: threshold_output.unlink(missing_ok=True)
        if (rescue / config.name).exists(): atomic_copy(rescue / config.name, config)
        prod = rescue / ("production-" + threshold_target.name)
        if prod.exists(): atomic_copy(prod, threshold_target)
        elif not current_target_exists: threshold_target.unlink(missing_ok=True)
        return 33

def die(message: str, code: int = 1):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def human_path(path: Path) -> str:
    try:
        return str(path.resolve())
    except Exception:
        return str(path)


def apply_policy(rules, policy):
    unresolved_selective = Counter()
    unknown_count = 0
    unknown_enabled = 0

    for rule in rules.values():
        rule.category = core.map_category(rule.msg, policy)
        if rule.category is None:
            unknown_count += 1
            if rule.source_enabled:
                unknown_enabled += 1
        enabled, reason = core.base_policy_decision(rule, policy, unresolved_selective)
        rule.initial_enabled = enabled
        rule.reason = reason

    overrides = core.apply_explicit_overrides(rules, policy)
    restored_flow, restored_xbit, missing_flow, missing_xbit, ambiguous_flow, ambiguous_xbit = core.resolve_dependencies(rules, policy)
    dependency_trace = dict(getattr(core.resolve_dependencies, "last_trace", {}) or {})

    return {
        "unresolved_selective": unresolved_selective,
        "unknown_count": unknown_count,
        "unknown_enabled": unknown_enabled,
        "explicit_keep": overrides["tracked_enabled_sids"] | overrides["semantic_keep_sids"],
        "tracked_keep": overrides["tracked_keep_sids"],
        "semantic_keep": overrides["semantic_keep_sids"],
        "missing_explicit": overrides["missing_tracked_sids"],
        "tracked_feed_disabled": overrides["tracked_feed_disabled_sids"],
        "restored_flow": restored_flow,
        "restored_xbit": restored_xbit,
        "missing_flow": missing_flow,
        "missing_xbit": missing_xbit,
        "ambiguous_flow": ambiguous_flow,
        "ambiguous_xbit": ambiguous_xbit,
        "dependency_graph": dependency_trace,
    }


def tracked_sid_set(policy: dict) -> set[int]:
    out = set()
    for _cat, cfg in (policy.get("rule_overrides", {}) or {}).items():
        for sid in cfg.get("tracked_keep_sids", cfg.get("explicit_keep_sids", [])) or []:
            out.add(int(sid))
    return out


def build_tracked_baseline(rules, policy: dict) -> dict:
    items = {}
    for sid in sorted(tracked_sid_set(policy)):
        r = rules.get(sid)
        if not r:
            continue
        items[str(sid)] = {
            "category": r.category or "UNMAPPED",
            "rev": r.rev,
            "msg": r.msg,
            "logic_sha256": core.rule_logic_sha256(r.raw),
            "raw_sha256": core.rule_raw_sha256(r.raw),
        }
    return {
        "version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tracked_rules": items,
    }


def audit_tracked_rules(rules, policy: dict, baseline_path: Path) -> dict:
    tracked = tracked_sid_set(policy)
    baseline = {}
    baseline_version = 0
    if baseline_path.exists():
        try:
            baseline_doc = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline = baseline_doc.get("tracked_rules", {})
            baseline_version = int(baseline_doc.get("version", 1))
        except Exception:
            baseline = {}
            baseline_version = 0
    result = {
        "tracked": len(tracked), "ok": [], "unbaselined": [], "missing": [], "feed_disabled": [],
        "rev_changed": [], "logic_changed": [], "message_changed": [], "category_changed": [],
        "baseline_missing": not bool(baseline), "baseline_version": baseline_version,
    }
    for sid in sorted(tracked):
        r = rules.get(sid)
        if not r:
            result["missing"].append(sid); continue
        if not r.source_enabled:
            result["feed_disabled"].append(sid)
        old = baseline.get(str(sid))
        if not old:
            result["unbaselined"].append(sid)
            continue
        changed = False
        if int(old.get("rev", 0)) != r.rev:
            result["rev_changed"].append(sid); changed = True
        logic_hash = core.rule_logic_sha256_v1(r.raw) if baseline_version <= 1 else core.rule_logic_sha256(r.raw)
        if old.get("logic_sha256") and old.get("logic_sha256") != logic_hash:
            result["logic_changed"].append(sid); changed = True
        if old.get("msg") != r.msg:
            result["message_changed"].append(sid); changed = True
        if old.get("category") != (r.category or "UNMAPPED"):
            result["category_changed"].append(sid); changed = True
        if not changed:
            result["ok"].append(sid)
    return result


def print_tracked_audit(audit: dict, baseline_path: Path):
    print("\n\n TRACKED SID INTEGRITY")
    print("------------------------------------------------------------")
    print(f" Tracked exceptions : {audit['tracked']:,}")
    print(f" Unchanged           : {len(audit['ok']):,}")
    print(f" No baseline entry   : {len(audit.get('unbaselined', [])):,}")
    print(f" REV changed         : {len(audit['rev_changed']):,}")
    print(f" Logic changed       : {len(audit['logic_changed']):,}")
    print(f" Message changed     : {len(audit['message_changed']):,}")
    print(f" Category changed    : {len(audit['category_changed']):,}")
    print(f" Missing             : {len(audit['missing']):,}")
    print(f" Feed-disabled       : {len(audit['feed_disabled']):,}")
    if audit["baseline_missing"]:
        print(f" Baseline            : missing ({baseline_path})")
    if audit["logic_changed"] or audit["missing"] or audit["category_changed"]:
        print(" REVIEW REQUIRED: tracked rule identity/logic drift detected.")


def write_tuned_rules(output: Path, rules, policy_path: Path, rules_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    enabled = [r for r in rules.values() if r.final_enabled]
    now = datetime.now(timezone.utc).isoformat()
    tmp = output.with_name(output.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# ============================================================\n")
        f.write("# AUTO-GENERATED SURICATA TUNED RULESET\n")
        f.write("# Do not edit this file manually. Edit tuning-policy.yaml.\n")
        f.write(f"# Generated: {now}\n")
        f.write(f"# Source: {rules_path}\n")
        f.write(f"# Policy: {policy_path}\n")
        f.write(f"# Enabled rules: {len(enabled)}\n")
        f.write(f"# Source SHA256: {core.sha256_file(rules_path)}\n")
        f.write(f"# Policy SHA256: {core.sha256_file(policy_path)}\n")
        f.write("# ============================================================\n\n")
        for rule in enabled:
            f.write(rule.raw.rstrip() + "\n")
    tmp.replace(output)


def gid_for_rule(rule) -> int:
    values = core.option_values(rule.raw, "gid")
    if not values:
        return 1
    try:
        return int(values[-1].strip())
    except ValueError:
        return 1


def write_threshold_config(path: Path, rules, policy: dict) -> dict:
    cfg = policy.get("alert_tuning", {}) or {}
    profiles = cfg.get("profiles", {}) or {}
    raw_overrides = cfg.get("sid_overrides", {}) or {}
    sid_overrides = {}
    for raw_sid, value in raw_overrides.items():
        try:
            sid_overrides[int(raw_sid)] = value or {}
        except (TypeError, ValueError):
            continue
    enabled = bool(cfg.get("enabled", True))
    lines = [MANAGED_BEGIN,
             "# Auto-generated by tune_rules.py. Edit tuning-policy.yaml, not this block."]
    generated = 0
    skipped_inline = 0
    override_generated = 0
    category_counts = Counter()

    if enabled:
        for rule in sorted(rules.values(), key=lambda r: r.sid):
            if not rule.final_enabled:
                continue
            override = sid_overrides.get(rule.sid)
            if override is not None and not bool(override.get("enabled", True)):
                continue

            # SID overrides are patches, not standalone profiles. Start from the
            # category profile (when present) and replace only the fields explicitly
            # supplied for this SID. This keeps track/type/seconds/count inheritance
            # predictable when an analyst wants to change just one parameter.
            base_prof = profiles.get(rule.category) or {}
            if override is not None:
                prof = dict(base_prof)
                prof.update({k: v for k, v in override.items() if k != "enabled"})
            else:
                prof = base_prof
            if not prof:
                continue
            option_keys = {key for key, _value in core.split_rule_options(rule.raw)}
            # Do not override a threshold/detection_filter deliberately authored by the feed.
            if "threshold" in option_keys or "detection_filter" in option_keys:
                skipped_inline += 1
                continue
            typ = str(prof.get("type", "limit"))
            track = str(prof.get("track", "by_src"))
            count = int(prof.get("count", 1))
            seconds = int(prof.get("seconds", 300))
            lines.append(
                f"threshold gen_id {gid_for_rule(rule)}, sig_id {rule.sid}, "
                f"type {typ}, track {track}, count {count}, seconds {seconds}"
            )
            generated += 1
            if override is not None:
                override_generated += 1
            category_counts[rule.category or "UNMAPPED"] += 1

        for item in cfg.get("suppressions", []) or []:
            if not isinstance(item, dict) or "sid" not in item:
                continue
            sid = int(item["sid"])
            gid = int(item.get("gid", 1))
            track = item.get("track")
            ip = item.get("ip")
            if track and ip:
                lines.append(f"suppress gen_id {gid}, sig_id {sid}, track {track}, ip {ip}")
            else:
                lines.append(f"suppress gen_id {gid}, sig_id {sid}")

    lines.append(MANAGED_END)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)
    return {
        "threshold_entries": generated,
        "skipped_rules_with_inline_threshold": skipped_inline,
        "by_category": dict(sorted(category_counts.items())),
        "suppression_entries": len(cfg.get("suppressions", []) or []),
        "sid_override_entries": override_generated,
    }


def category_stats(rules, policy):
    stats = {}
    for cat, cfg in (policy.get("categories", {}) or {}).items():
        stats[cat] = {
            "mode": cfg.get("mode", "unknown"),
            "strategy": cfg.get("strategy"),
            "parsed": 0,
            "feed_enabled": 0,
            "final_enabled": 0,
        }
    for r in rules.values():
        cat = r.category or "UNMAPPED"
        if cat not in stats:
            stats[cat] = {"mode": "unknown", "strategy": None, "parsed": 0, "feed_enabled": 0, "final_enabled": 0}
        stats[cat]["parsed"] += 1
        if r.source_enabled:
            stats[cat]["feed_enabled"] += 1
        if r.final_enabled:
            stats[cat]["final_enabled"] += 1
    return stats


def mode_summary(stats):
    out = {}
    for _cat, st in stats.items():
        if not st["parsed"]:
            continue
        mode = "preserve_feed" if st["mode"] == "keep" else st["mode"]
        row = out.setdefault(mode, {"categories": 0, "parsed": 0, "feed_enabled": 0, "final_enabled": 0})
        row["categories"] += 1
        row["parsed"] += st["parsed"]
        row["feed_enabled"] += st["feed_enabled"]
        row["final_enabled"] += st["final_enabled"]
    return out


def retained_dependency_count(category, rules):
    return sum(1 for r in rules.values()
               if r.category == category and r.final_enabled and r.restored_dependency_types)


def print_friendly_summary(policy, rules, result, threshold_result):
    stats = category_stats(rules, policy)
    modes = mode_summary(stats)

    def print_simple_header(context_title):
        print("   " + "CATEGORY".ljust(26) + "TOTAL RULES".rjust(13) + "ACTIVE NOW".rjust(13) + "   " + context_title)
        print("   " + "-" * 96)

    def print_simple_row(cat, st, note=""):
        print("   " + f"{cat:<26}{st['parsed']:>13,}{st['final_enabled']:>13,}   {note}")

    print("\n\n============================================================")
    print(" POLICY STATUS SUMMARY")
    print("------------------------------------------------------------")
    for mode in ("preserve_feed", "conditional", "asset_based", "disable", "unknown"):
        row = modes.get(mode)
        if row and not (mode == "unknown" and row["feed_enabled"] == 0 and row["final_enabled"] == 0):
            label = mode.upper()
            print(f" {label:15} {row['categories']:>2} categories | Total rules: {row['parsed']:,} | Active now: {row['final_enabled']:,}")

    print("\n\n ADMIN RECOMMENDATIONS")
    print("------------------------------------------------------------")
    print(" !!! REMEMBER: A DISABLED RULE IS NOT NECESSARILY USELESS !!!")

    print("\n\n [ASSET-BASED] Confirm these against your real asset inventory:\n")
    print_simple_header("ASSET CONTEXT")
    assets = policy.get("assets", {}) or {}
    for cat, cfg in (policy.get("categories", {}) or {}).items():
        if cfg.get("mode") != "asset_based" or not stats.get(cat, {}).get("parsed"):
            continue
        st = stats[cat]
        detail = ""
        if cat == "ET_WEB_SPECIFIC_APPS":
            apps = assets.get("web_specific_apps", {}) or {}
            enabled_apps = []
            for name, app_cfg in apps.items():
                en = app_cfg if isinstance(app_cfg, bool) else bool((app_cfg or {}).get("enabled", False)) if isinstance(app_cfg, dict) else False
                if en:
                    enabled_apps.append(name)
            detail = "enabled apps: " + (", ".join(enabled_apps) if enabled_apps else "none")
        elif cat == "ET_WEB_SERVER":
            detail = f"web_server={bool((assets.get('web_server', {}) or {}).get('enabled', False))}"
        elif cat == "ET_SCADA":
            detail = f"scada={bool((assets.get('scada', {}) or {}).get('enabled', False))}"
        elif cat == "ET_ACTIVEX":
            detail = f"activex={bool((assets.get('activex', {}) or {}).get('enabled', False))}"
        elif cat == "ET_VOIP":
            detail = f"voip={bool((assets.get('voip', {}) or {}).get('enabled', False))}"
        print_simple_row(cat, st, detail)

    asset_review_count = sum(1 for r in rules.values() if r.asset_review_candidate)
    if asset_review_count:
        print(f"\n   Asset rules requiring manual review: {asset_review_count:,}")

    print("\n\n [CONDITIONAL] Context/policy dependent:\n")
    print_simple_header("POLICY / REASON")
    order = [
        "ET_REMOTE_ACCESS", "ET_TOR", "ET_FILE_SHARING", "ET_P2P", "ET_CHAT", "ET_DYN_DNS",
        "ET_TA_ABUSED_SERVICES", "ET_ADWARE_PUP", "ET_HUNTING", "ET_USER_AGENTS", "SURICATA",
        "ET_JA3", "ET_CINS", "ET_DNS", "ET_DROP", "ET_SMTP", "GPL_MISC", "ET_INFO", "ET_TFTP"
    ]
    org = policy.get("organization_policy", {}) or {}
    cats_cfg = policy.get("categories", {}) or {}
    for cat in order:
        st = stats.get(cat)
        if not st or not st["parsed"]:
            continue
        cfg = cats_cfg.get(cat, {}) or {}
        strategy = cfg.get("strategy", "")
        if cat == "ET_REMOTE_ACCESS":
            x = org.get("remote_access", {}) or {}
            note = f"policy={x.get('default_policy', 'unset')}; detection={bool(x.get('detection_enabled', False))}"
        elif cat == "ET_TOR":
            x = org.get("tor", {}) or {}
            note = f"prohibited={x.get('prohibited')}; detection={bool(x.get('detection_enabled', False))}"
        elif cat in {"ET_FILE_SHARING", "ET_P2P", "ET_CHAT", "ET_DYN_DNS"}:
            key = {"ET_FILE_SHARING":"file_sharing", "ET_P2P":"p2p", "ET_CHAT":"chat", "ET_DYN_DNS":"dynamic_dns"}[cat]
            x = org.get(key, {}) or {}
            note = f"admin decision={x.get('prohibited')}; detection={bool(x.get('detection_enabled', False))}"
            dep = retained_dependency_count(cat, rules)
            if dep:
                note += f"; dependency-retained={dep}"
        elif strategy == "message_filter":
            terms = ((cfg.get("message_filter", {}) or {}).get("disable_contains", []) or [])
            note = "preserve anomalies; filtered: " + (", ".join(terms) if terms else "configured message patterns")
            if cfg.get("alert_tuning"):
                note += "; alert-tuned"
        elif strategy == "enabled_by_default_with_alert_tuning":
            note = "enabled; generated threshold policy"
        elif strategy == "enabled_by_default":
            note = "enabled; supporting signal/correlation"
        elif strategy == "default_disabled_with_allowlist":
            note = f"default OFF; allowlist/dependencies retained; dependency-restored={retained_dependency_count(cat, rules)}"
        elif strategy == "disabled_by_default":
            note = f"default OFF unless organization policy enables it; dependency-restored={retained_dependency_count(cat, rules)}"
        else:
            note = strategy or "conditional"
        print_simple_row(cat, st, note)

    hard = []
    intentional_disabled_total = 0
    for cat, cfg in cats_cfg.items():
        st = stats.get(cat)
        if cfg.get("mode") == "disable" and st and st["parsed"]:
            hard.append((cat, st))
            intentional_disabled_total += max(st["parsed"] - st["final_enabled"], 0)
    if hard:
        print("\n\n [INTENTIONAL DISABLE] Currently treated as low-value/retired:\n")
        for cat, st in hard:
            print(f"   - {cat}")
            print(f"     Total rules : {st['parsed']:,}")
            print(f"     Active now  : {st['final_enabled']:,}")
            print(f"     Disabled now: {max(st['parsed'] - st['final_enabled'], 0):,}\n")
        print(f"   TOTAL INTENTIONALLY DISABLED: {intentional_disabled_total:,} rules")

    print("\n\n [ALERT TUNING]")
    print(f"   Generated threshold entries : {threshold_result.get('threshold_entries', 0):,}")
    print(f"   Explicit suppressions        : {threshold_result.get('suppression_entries', 0):,}")
    print(f"   Existing inline thresholds   : {threshold_result.get('skipped_rules_with_inline_threshold', 0):,} preserved")

    if result["unresolved_selective"]:
        print("\n\n [ADMIN REVIEW REQUIRED]")
        for cat in sorted(result["unresolved_selective"]):
            st = stats.get(cat, {"parsed": 0, "final_enabled": 0})
            print(f"   - {cat}: Total rules={st['parsed']:,}, Active now={st['final_enabled']:,}")

    print("\n============================================================")
    return stats, modes


def build_report(args, output: Path, threshold_output: Path, rules, result: dict, threshold_result: dict) -> dict:
    source_enabled = sum(1 for r in rules.values() if r.source_enabled)
    final_enabled = sum(1 for r in rules.values() if r.final_enabled)
    by_category = Counter((r.category or "UNMAPPED") for r in rules.values() if r.final_enabled)
    disabled = source_enabled - sum(1 for r in rules.values() if r.source_enabled and r.final_enabled)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_rules": human_path(args.rules),
        "policy": human_path(args.policy),
        "output": human_path(output),
        "threshold_output": human_path(threshold_output),
        "input_sha256": core.sha256_file(args.rules),
        "policy_sha256": core.sha256_file(args.policy),
        "parsed_rules": len(rules),
        "feed_enabled_before_tuning": source_enabled,
        "final_enabled_rules": final_enabled,
        "feed_enabled_removed_by_policy": disabled,
        "explicit_keep_sids": len(result["explicit_keep"]),
        "semantic_keep_sids": len(result.get("semantic_keep", [])),
        "tracked_keep_sids": len(result.get("tracked_keep", [])),
        "tracked_feed_disabled_sids": sorted(result.get("tracked_feed_disabled", [])),
        "flowbit_dependency_sids_restored": len(result["restored_flow"]),
        "xbit_dependency_sids_restored": len(result["restored_xbit"]),
        "missing_flowbit_setters": sorted(result["missing_flow"]),
        "missing_xbit_setters": sorted(result["missing_xbit"]),
        "ambiguous_flowbit_toggle_dependencies": sorted(result.get("ambiguous_flow", [])),
        "ambiguous_xbit_toggle_dependencies": sorted(result.get("ambiguous_xbit", [])),
        "missing_explicit_keep_sids": sorted(result["missing_explicit"]),
        "unknown_category_rules": result["unknown_count"],
        "unknown_category_enabled_rules": result["unknown_enabled"],
        "pending_selective_categories": dict(sorted(result["unresolved_selective"].items())),
        "threshold_policy": threshold_result,
        "asset_review_candidates": [
            {"sid": r.sid, "category": r.category, "msg": r.msg, "asset": r.asset_match_asset,
             "status": getattr(r, "asset_match_status", "unknown"),
             "score": r.asset_match_score, "evidence": r.asset_match_evidence,
             "candidates": getattr(r, "asset_match_candidates", [])}
            for r in rules.values() if r.asset_review_candidate
        ],
        "dependency_graph": result.get("dependency_graph", {}),
        "final_enabled_by_category": dict(sorted(by_category.items())),
    }


def current_state(rules, input_hash: str, policy_hash: str) -> dict:
    return {
        "version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_sha256": input_hash,
        "policy_sha256": policy_hash,
        "rules": {
            str(r.sid): {
                "rev": r.rev,
                "enabled": bool(r.final_enabled),
                "source_enabled": bool(r.source_enabled),
                "category": r.category or "UNMAPPED",
            }
            for r in rules.values()
        },
    }


def compute_diff(previous: Optional[dict], current: dict) -> dict:
    if not previous or not isinstance(previous.get("rules"), dict):
        return {"baseline": True, "new_sids": [], "removed_sids": [], "rev_changed": [],
                "newly_enabled": [], "newly_disabled": []}
    old = previous["rules"]
    new = current["rules"]
    old_ids, new_ids = set(old), set(new)
    common = old_ids & new_ids
    return {
        "baseline": False,
        "new_sids": sorted(int(x) for x in new_ids - old_ids),
        "removed_sids": sorted(int(x) for x in old_ids - new_ids),
        "rev_changed": sorted(int(x) for x in common if int(old[x].get("rev", 0)) != int(new[x].get("rev", 0))),
        "newly_enabled": sorted(int(x) for x in common if not old[x].get("enabled", False) and new[x].get("enabled", False)),
        "newly_disabled": sorted(int(x) for x in common if old[x].get("enabled", False) and not new[x].get("enabled", False)),
    }


def write_diff_reports(txt_path: Path, diff: dict) -> Path:
    """Write the single user-visible diff report.

    Detailed SID lists live in the same text file so tuning no longer creates a
    second ``.json`` sidecar next to the ruleset.
    """
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["RULESET DIFF", "============"]
    if diff["baseline"]:
        lines += ["Baseline created: no previous tuner state was found.", ""]
    else:
        lines += [
            f"New SIDs       : {len(diff['new_sids']):,}",
            f"Removed SIDs   : {len(diff['removed_sids']):,}",
            f"REV changed    : {len(diff['rev_changed']):,}",
            f"Newly enabled  : {len(diff['newly_enabled']):,}",
            f"Newly disabled : {len(diff['newly_disabled']):,}",
            "",
        ]
    for key, label in (
        ("new_sids", "New SIDs"),
        ("removed_sids", "Removed SIDs"),
        ("rev_changed", "REV changed"),
        ("newly_enabled", "Newly enabled"),
        ("newly_disabled", "Newly disabled"),
    ):
        values = diff.get(key, []) or []
        lines.append(label + ":")
        lines.append("  " + (", ".join(str(x) for x in values) if values else "None"))
        lines.append("")
    atomic_write_text(txt_path, "\n".join(lines).rstrip() + "\n")
    txt_path.with_suffix(txt_path.suffix + ".json").unlink(missing_ok=True)
    return txt_path


def print_diff_summary(diff: dict):
    print("\n\n RULESET DIFF")
    print("------------------------------------------------------------")
    if diff["baseline"]:
        print(" Baseline created; no previous run exists yet.")
    else:
        print(f" New SIDs       : {len(diff['new_sids']):,}")
        print(f" Removed SIDs   : {len(diff['removed_sids']):,}")
        print(f" REV changed    : {len(diff['rev_changed']):,}")
        print(f" Newly enabled  : {len(diff['newly_enabled']):,}")
        print(f" Newly disabled : {len(diff['newly_disabled']):,}")


def print_insights(bundle: dict):
    health = bundle.get("policy_health", {}) or {}
    recs = bundle.get("recommendations", []) or []
    impact = bundle.get("update_impact", {}) or {}

    print("\n\n POLICY HEALTH")
    print("------------------------------------------------------------")
    print(f" Configuration health : {health.get('score', '?')}/100 ({health.get('status', 'UNKNOWN')})")
    print(" NOTE: this is policy/configuration health, not a security coverage score.")
    print(f" Actionable findings  : {health.get('actionable_findings', 0)}")

    print("\n\n RECOMMENDATIONS")
    print("------------------------------------------------------------")
    actionable = [r for r in recs if r.get("severity") != "info"]
    shown = actionable if actionable else recs
    for idx, rec in enumerate(shown[:12], 1):
        print(f" {idx:>2}. [{str(rec.get('severity','info')).upper()}] {rec.get('title','')}")
        print(f"     {rec.get('action','')}")
    if len(shown) > 12:
        print(f"     ... {len(shown)-12} more finding(s) are in the JSON report.")

    print("\n\n UPDATE IMPACT PREVIEW")
    print("------------------------------------------------------------")
    if impact.get("baseline", True):
        print(" No previous tuner state exists; this run creates the comparison baseline.")
    else:
        print(f" New SIDs             : {impact.get('new_sids',0):,}  (final active: {impact.get('new_final_enabled',0):,})")
        print(f" Removed SIDs         : {impact.get('removed_sids',0):,}  (were active: {impact.get('removed_were_enabled',0):,})")
        print(f" REV changed          : {impact.get('rev_changed',0):,}")
        print(f" Newly enabled        : {impact.get('newly_enabled',0):,}")
        print(f" Newly disabled       : {impact.get('newly_disabled',0):,}")
        print(f" Changed SIDs review  : {impact.get('review_count',0):,}")
        cats = impact.get("categories", {}) or {}
        if cats:
            print(" Top affected categories:")
            for cat, counts in list(cats.items())[:8]:
                total = sum(int(v) for v in counts.values())
                detail = ", ".join(f"{k}={v}" for k,v in counts.items())
                print(f"   - {cat}: {total} ({detail})")


def validation_settings(policy: dict) -> dict:
    cfg = policy.get("validation", {}) or {}
    return {
        "require_suricata_test": bool(cfg.get("require_suricata_test", False)),
        "check_flowbit_dependencies": bool(cfg.get("check_flowbit_dependencies", True)),
        "check_xbit_dependencies": bool(cfg.get("check_xbit_dependencies", True)),
        "require_ja3_fingerprinting": bool(cfg.get("require_ja3_fingerprinting", False)),
        "require_explicit_ja3_fingerprinting": bool(cfg.get("require_explicit_ja3_fingerprinting", False)),
        "generate_diff_report": bool(cfg.get("generate_diff_report", True)),
    }


def _nested_mapping_value(data, path):
    cur = data
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _truthy_config_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return False


def _ja3_setting_state(value) -> str:
    """Normalize a JA3 config value to enabled/disabled/auto/unknown."""
    if value is None:
        return "auto"
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if isinstance(value, (int, float)):
        return "enabled" if value != 0 else "disabled"
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on", "enabled"}:
            return "enabled"
        if text in {"0", "false", "no", "off", "disabled"}:
            return "disabled"
        if text in {"auto", "default", ""}:
            return "auto"
    return "unknown"


def ja3_fingerprinting_status(config: Path) -> tuple[str, str]:
    """Inspect JA3 configuration using Suricata semantics.

    Suricata 8 enables JA3 on demand when a loaded rule requires it unless the
    feature is explicitly disabled. Therefore an absent setting is ``auto`` and is
    valid for ordinary prerequisite checking. ``suricata -T`` remains the final
    authority for build-time feature availability and the effective configuration.
    """
    if not config.exists():
        return "unknown", f"config not found: {config}"

    binary = shutil.which("suricata")
    if binary:
        try:
            proc = subprocess.run(
                [binary, "-c", str(config), "--dump-config"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                m = re.search(
                    r"(?mi)^\s*app-layer\.protocols\.tls\.ja3-fingerprints\s*[:=]\s*([^\s#]+)",
                    proc.stdout,
                )
                if m:
                    value = m.group(1).strip().strip('"\'')
                    state = _ja3_setting_state(value)
                    return state, (
                        "effective app-layer.protocols.tls.ja3-fingerprints=" + repr(value)
                    )
                # Missing from the effective dump is not equivalent to explicit no.
                # Rules that require JA3 can enable it on demand in Suricata 8.
                return "auto", "JA3 setting is not explicitly set; Suricata may enable it on demand for loaded JA3 rules"
        except (OSError, subprocess.SubprocessError):
            pass

    try:
        data = core.yaml.safe_load(config.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception as exc:
        return "unknown", f"could not parse config YAML: {exc}"
    value = _nested_mapping_value(data, ("app-layer", "protocols", "tls", "ja3-fingerprints"))
    state = _ja3_setting_state(value)
    if value is None:
        return state, "JA3 setting is not explicitly set; Suricata may enable it on demand for loaded JA3 rules"
    return state, f"app-layer.protocols.tls.ja3-fingerprints={value!r}"


def ja3_fingerprinting_enabled(config: Path) -> tuple[bool, str]:
    """Backward-compatible helper: auto is usable unless explicitly disabled."""
    state, detail = ja3_fingerprinting_status(config)
    return state in {"enabled", "auto"}, detail


def rule_requires_ja3(rule) -> bool:
    if not rule.final_enabled:
        return False
    # Current sticky-buffer keywords plus legacy spellings still found in older feeds.
    keys = {key for key, _value in core.split_rule_options(rule.raw)}
    return bool(keys & {"ja3.hash", "ja3.string", "ja3s.hash", "ja3s.string",
                        "ja3_hash", "ja3_string", "ja3s_hash", "ja3s_string"})


def policy_validation_preflight(rules, result: dict, policy: dict, config: Path) -> dict:
    cfg = validation_settings(policy)
    checks = []
    failures = []

    # Duplicate SID detection is a non-configurable parser safety invariant.
    # core.load_rules rejects duplicates before policy evaluation begins.
    checks.append({"name": "duplicate_sid", "required": True, "ok": True,
                   "detail": "always enforced by parser (not configurable)"})

    flow_ok = not bool(result.get("missing_flow"))
    checks.append({"name": "flowbit_dependencies", "required": cfg["check_flowbit_dependencies"],
                   "ok": flow_ok, "detail": sorted(result.get("missing_flow", []))})
    if cfg["check_flowbit_dependencies"] and not flow_ok:
        failures.append(f"unresolved flowbit dependency groups: {', '.join(sorted(result['missing_flow']))}")

    xbit_ok = not bool(result.get("missing_xbit"))
    checks.append({"name": "xbit_dependencies", "required": cfg["check_xbit_dependencies"],
                   "ok": xbit_ok, "detail": sorted(result.get("missing_xbit", []))})
    if cfg["check_xbit_dependencies"] and not xbit_ok:
        failures.append(f"unresolved xbit dependencies: {', '.join(sorted(result['missing_xbit']))}")

    ambiguous_flow = sorted(result.get("ambiguous_flow", []))
    ambiguous_xbit = sorted(result.get("ambiguous_xbit", []))
    checks.append({"name": "toggle_only_dependencies", "required": False,
                   "ok": not bool(ambiguous_flow or ambiguous_xbit),
                   "detail": {"flowbits": ambiguous_flow, "xbits": ambiguous_xbit,
                              "note": "toggle flips state and is not auto-restored as a guaranteed setter"}})

    ja3_active = any(rule_requires_ja3(r) for r in rules.values())
    ja3_required = bool(
        ja3_active
        and (cfg["require_ja3_fingerprinting"] or cfg["require_explicit_ja3_fingerprinting"])
    )
    ja3_ok = True
    ja3_detail = "not required for current final ruleset"
    ja3_state = "not_required"
    if ja3_required:
        ja3_state, ja3_detail = ja3_fingerprinting_status(config)
        if ja3_state in {"disabled", "unknown"}:
            ja3_ok = False
            failures.append(
                f"JA3 rules are enabled but JA3 fingerprinting prerequisite failed: {ja3_detail}"
            )
        elif cfg["require_explicit_ja3_fingerprinting"] and ja3_state != "enabled":
            ja3_ok = False
            failures.append(
                "JA3 rules are enabled and policy requires an explicit "
                f"ja3-fingerprints: yes setting: {ja3_detail}"
            )
    checks.append({
        "name": "ja3_fingerprinting",
        "required": ja3_required,
        "ok": ja3_ok,
        "state": ja3_state,
        "detail": ja3_detail,
    })

    return {"settings": cfg, "checks": checks, "failures": failures, "ok": not failures}


def run_suricata_test(output: Path, threshold_output: Path, config: Path, production: bool = False) -> int:
    binary = shutil.which("suricata")
    if not binary:
        print("\n[TEST] SKIPPED: 'suricata' binary was not found in PATH.")
        return 3
    if not config.exists():
        print(f"\n[TEST] FAILED: Suricata config not found: {config}", file=sys.stderr)
        return 4
    if production:
        cmd = [binary, "-T", "-c", str(config)]
    else:
        cmd = [binary, "-T", "-c", str(config), "-S", str(output), "--set", f"threshold-file={threshold_output}"]
    print("\n[TEST] Running Suricata configuration/rule test...")
    print("       " + " ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode == 0:
        print("[TEST] PASS")
    else:
        print(f"[TEST] FAIL (exit={proc.returncode})", file=sys.stderr)
    return proc.returncode


def extract_yaml_scalar(config_text: str, key: str) -> Optional[str]:
    m = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*([^#\n]+)", config_text)
    if not m:
        return None
    return m.group(1).strip().strip('"\'')


def patch_rule_files(config: Path, output: Path, replace_names: Optional[set[str]] = None) -> tuple[str, bool]:
    text = config.read_text(encoding="utf-8")
    default_rule_path = extract_yaml_scalar(text, "default-rule-path")
    try:
        use_name = output.name if default_rule_path and output.parent.resolve() == Path(default_rule_path).resolve() else str(output.resolve())
    except Exception:
        use_name = str(output)
    replace_names = set(replace_names or {"suricata.rules", output.name})

    lines = text.splitlines(keepends=True)
    start = None
    base_indent = 0
    for i, line in enumerate(lines):
        if re.match(r"^\s*rule-files\s*:\s*(?:#.*)?$", line):
            start = i
            base_indent = len(line) - len(line.lstrip())
            break
    if start is None:
        raise RuntimeError("Could not find 'rule-files:' in suricata.yaml")

    changed = False
    found_tuned = False
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            break
        m = re.match(r"^(\s*)-\s*['\"]?([^'\"#\n]+)['\"]?(\s*(?:#.*)?)$", line.rstrip("\n"))
        if not m:
            continue
        value = m.group(2).strip()
        current_name = Path(value).name
        if current_name == output.name:
            found_tuned = True
        elif current_name in replace_names:
            newline = "\n" if line.endswith("\n") else ""
            lines[i] = f"{m.group(1)}- {use_name}{m.group(3)}{newline}"
            changed = True
            found_tuned = True
    if not found_tuned:
        names = ", ".join(sorted(replace_names))
        raise RuntimeError(f"No managed rule-files entry ({names}) was found; production config was not changed")
    if changed:
        atomic_write_text(config, "".join(lines))
    return use_name, changed


def configured_rule_files(config: Path) -> list[str]:
    """Return active entries under the top-level rule-files list."""
    text = config.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = None
    base_indent = 0
    entries: list[str] = []
    for i, line in enumerate(lines):
        if re.match(r"^\s*rule-files\s*:\s*(?:#.*)?$", line):
            start = i
            base_indent = len(line) - len(line.lstrip())
            break
    if start is None:
        return entries
    for line in lines[start + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            break
        m = re.match(r"^\s*-\s*['\"]?([^'\"#\n]+)['\"]?", line)
        if m:
            entries.append(m.group(1).strip())
    return entries


def config_uses_rule_file(config: Path, output: Path) -> bool:
    """Verify that suricata.yaml resolves at least one rule-files entry to output."""
    text = config.read_text(encoding="utf-8")
    default_rule_path = extract_yaml_scalar(text, "default-rule-path")
    base = Path(default_rule_path) if default_rule_path else config.parent
    try:
        expected = output.resolve()
    except Exception:
        expected = output
    for raw in configured_rule_files(config):
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = base / candidate
        try:
            candidate = candidate.resolve()
        except Exception:
            pass
        if candidate == expected:
            return True
    return False


def _running_suricata_cmdlines() -> list[list[str]]:
    """Best-effort /proc inspection without depending on pgrep/ps output formats."""
    rows: list[list[str]] = []
    proc = Path("/proc")
    if not proc.exists():
        return rows
    for child in proc.iterdir():
        if not child.name.isdigit():
            continue
        try:
            raw = (child / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        if not raw:
            continue
        parts = [x.decode("utf-8", errors="replace") for x in raw.split(b"\0") if x]
        if not parts:
            continue
        exe = Path(parts[0]).name.lower()
        # Do not match our own suricata-policy-engine process or helper tools.
        # The packet engine binary itself is named `suricata`.
        if exe == "suricata":
            rows.append(parts)
    return rows


def running_suricata_sigfile_overrides() -> list[str]:
    """Return rule files pinned with -S/--sig-file by running Suricata processes."""
    found: list[str] = []
    for parts in _running_suricata_cmdlines():
        for idx, token in enumerate(parts):
            if token in {"-S", "--sig-file"} and idx + 1 < len(parts):
                found.append(parts[idx + 1])
            elif token.startswith("--sig-file="):
                found.append(token.split("=", 1)[1])
    return found


def running_suricata_config_paths() -> list[str]:
    """Return explicit -c/--config paths used by running Suricata processes."""
    found: list[str] = []
    for parts in _running_suricata_cmdlines():
        for idx, token in enumerate(parts):
            if token in {"-c", "--config"} and idx + 1 < len(parts):
                found.append(parts[idx + 1])
            elif token.startswith("--config="):
                found.append(token.split("=", 1)[1])
    return found


def _same_config_target(raw: str, expected: Path) -> bool:
    candidate = Path(raw)
    if not candidate.is_absolute():
        # Runtime CWD is unknown, so a relative config path cannot be safely
        # proven to be the file we are editing.  Fail closed rather than claim
        # a live switch.
        return str(candidate) == str(expected)
    try:
        return candidate.resolve() == expected.resolve()
    except Exception:
        return str(candidate) == str(expected)


def _same_rule_target(raw: str, expected: Path) -> bool:
    candidate = Path(raw)
    if not candidate.is_absolute():
        # Do not accept a same-basename guess for a runtime -S override; the
        # process working directory may make it a different file.
        return str(candidate) == str(expected)
    try:
        return candidate.resolve() == expected.resolve()
    except Exception:
        return str(candidate) == str(expected)


def _print_child_output(proc: subprocess.CompletedProcess) -> None:
    out = (getattr(proc, "stdout", None) or "").strip()
    err = (getattr(proc, "stderr", None) or "").strip()
    if out:
        for line in out.splitlines():
            print(f"         {line}")
    if err:
        for line in err.splitlines():
            print(f"         {line}", file=sys.stderr)


def resolve_threshold_file(config: Path) -> Path:
    text = config.read_text(encoding="utf-8")
    configured = extract_yaml_scalar(text, "threshold-file")
    if configured:
        p = Path(configured)
        return p if p.is_absolute() else config.parent / p
    return Path("/etc/suricata/threshold.config")


def merge_managed_threshold(target: Path, generated: Path):
    block = generated.read_text(encoding="utf-8").strip() + "\n"
    old = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
    pattern = re.compile(re.escape(MANAGED_BEGIN) + r".*?" + re.escape(MANAGED_END) + r"\n?", re.S)
    cleaned = pattern.sub("", old).rstrip()
    new = (cleaned + "\n\n" if cleaned else "") + block
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, new)


def deploy_production(candidate_output: Path, candidate_threshold: Path, config: Path, no_reload: bool,
                      final_output: Optional[Path] = None, final_threshold_output: Optional[Path] = None) -> int:
    if os.geteuid() != 0:
        print("[DEPLOY] FAILED: --deploy must be run as root/sudo.", file=sys.stderr)
        return 20
    if not config.exists():
        print(f"[DEPLOY] FAILED: config not found: {config}", file=sys.stderr)
        return 21

    final_output = final_output or candidate_output
    final_threshold_output = final_threshold_output or candidate_threshold

    sig_overrides = running_suricata_sigfile_overrides()
    conflicting = [raw for raw in sig_overrides if not _same_rule_target(raw, final_output)]
    if conflicting:
        print(
            "[DEPLOY] FAILED: the running Suricata process is pinned with -S/--sig-file, so changing "
            "suricata.yaml rule-files would NOT switch the live engine.",
            file=sys.stderr,
        )
        for raw in conflicting:
            print(f"         runtime signature override: {raw}", file=sys.stderr)
        print(
            "         Remove/update the -S override (preferred) or use a deployment model that intentionally manages that file.",
            file=sys.stderr,
        )
        return 28

    runtime_configs = running_suricata_config_paths()
    conflicting_configs = [raw for raw in runtime_configs if not _same_config_target(raw, config)]
    if conflicting_configs:
        print(
            "[DEPLOY] FAILED: the running Suricata process is using a different -c/--config file, "
            "so editing this suricata.yaml would NOT switch the live engine.",
            file=sys.stderr,
        )
        print(f"         requested config: {config}", file=sys.stderr)
        for raw in conflicting_configs:
            print(f"         runtime config:   {raw}", file=sys.stderr)
        return 29

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = config.parent / "tuner-backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    threshold_target = resolve_threshold_file(config)
    shutil.copy2(config, backup_dir / config.name)
    threshold_existed = threshold_target.exists()
    if threshold_existed:
        shutil.copy2(threshold_target, backup_dir / threshold_target.name)
    final_output_existed = final_output.exists()
    final_threshold_existed = final_threshold_output.exists()
    if final_output_existed:
        shutil.copy2(final_output, backup_dir / ("artifact-" + final_output.name))
    if final_threshold_existed:
        shutil.copy2(final_threshold_output, backup_dir / ("artifact-" + final_threshold_output.name))

    print("\n[DEPLOY] Installing validated candidate as production ruleset...")
    print(f"         Backup: {backup_dir}")
    try:
        atomic_copy(candidate_output, final_output)
        atomic_copy(candidate_threshold, final_threshold_output)
        entry, changed = patch_rule_files(config, final_output)
        if not config_uses_rule_file(config, final_output):
            raise RuntimeError(f"suricata.yaml verification failed: rule-files does not resolve to {final_output}")
        merge_managed_threshold(threshold_target, final_threshold_output)
        print(f"         rule-files entry : {entry}")
        print(f"         threshold-file   : {threshold_target}")
        if changed:
            print("         suricata.yaml     : updated")
        else:
            print("         suricata.yaml     : already points to tuned rules")

        rc = run_suricata_test(final_output, final_threshold_output, config, production=True)
        if rc != 0:
            raise RuntimeError("production Suricata test failed")

        if no_reload:
            print("[DEPLOY] Config installed. Reload skipped by --no-reload.")
            return 0

        rc = reload_suricata(final_output, config)
        if rc == 0:
            print("[DEPLOY] PASS: production configuration installed and activation state reported above.")
            return 0
        raise RuntimeError("Suricata reload/restart failed")

    except Exception as exc:
        print(f"[DEPLOY] ERROR: {exc}. Restoring config backup...", file=sys.stderr)
        shutil.copy2(backup_dir / config.name, config)
        if threshold_existed:
            atomic_copy(backup_dir / threshold_target.name, threshold_target)
        elif threshold_target.exists():
            threshold_target.unlink()
        artifact_rules = backup_dir / ("artifact-" + final_output.name)
        artifact_threshold = backup_dir / ("artifact-" + final_threshold_output.name)
        if final_output_existed and artifact_rules.exists():
            atomic_copy(artifact_rules, final_output)
        elif not final_output_existed:
            final_output.unlink(missing_ok=True)
        if final_threshold_existed and artifact_threshold.exists():
            atomic_copy(artifact_threshold, final_threshold_output)
        elif not final_threshold_existed:
            final_threshold_output.unlink(missing_ok=True)
        print("[DEPLOY] Rollback completed, including production artifacts.", file=sys.stderr)
        return 22


def replace_original_production(candidate_output: Path, candidate_threshold: Path, original_rules: Path,
                                tuned_output: Path, final_threshold_output: Path, config: Path,
                                no_reload: bool) -> int:
    """Destructive mode: atomically overwrite the original Suricata feed file.

    The candidate is already validated before this function is called.  We back up
    the original, install the exact candidate bytes at ``suricata.rules``, verify
    the SHA256, point ``rule-files`` back to the original path, validate production
    configuration, and then reload.  A post-install validation failure rolls back.
    A reload failure does *not* undo the requested overwrite after validation has
    passed; it is reported separately so file replacement semantics stay distinct
    from the normal Activate sidecar workflow.
    """
    if os.geteuid() != 0:
        print("[REPLACE] FAILED: --replace-original must be run as root/sudo.", file=sys.stderr)
        return 24
    if not config.exists():
        print(f"[REPLACE] FAILED: config not found: {config}", file=sys.stderr)
        return 25
    if not original_rules.exists():
        print(f"[REPLACE] FAILED: original rules not found: {original_rules}", file=sys.stderr)
        return 26

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_dir = default_state_dir() / "backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    threshold_target = resolve_threshold_file(config)

    shutil.copy2(config, backup_dir / config.name)
    shutil.copy2(original_rules, backup_dir / ("original-" + original_rules.name))
    threshold_existed = threshold_target.exists()
    if threshold_existed:
        shutil.copy2(threshold_target, backup_dir / threshold_target.name)

    print("\n[REPLACE] DESTRUCTIVE MODE: overwriting the original suricata.rules...")
    print(f"          Backup: {backup_dir}")
    installed = False
    try:
        # The production target in this mode is the original file itself.  Do not
        # touch the normal tuned sidecar until post-install validation succeeds.
        atomic_copy(candidate_output, original_rules)
        installed = True

        candidate_sha = core.sha256_file(candidate_output)
        original_sha = core.sha256_file(original_rules)
        if candidate_sha != original_sha:
            raise RuntimeError("post-write SHA256 verification failed; original file does not match candidate")

        entry, changed = patch_rule_files(
            config, original_rules, replace_names={original_rules.name, tuned_output.name}
        )
        merge_managed_threshold(threshold_target, candidate_threshold)
        print(f"          rule-files entry : {entry}")
        print(f"          overwritten file : {original_rules}")
        print(f"          verified SHA256  : {original_sha}")
        print(f"          suricata.yaml    : {'updated' if changed else 'already points to original rules'}")

        rc = run_suricata_test(original_rules, candidate_threshold, config, production=True)
        if rc != 0:
            raise RuntimeError("production Suricata test failed after original-rules replacement")

        # Keep one user-visible tuned artifact in sync with the validated replacement.
        atomic_copy(candidate_output, tuned_output)
        print(f"[REPLACE] FILE OVERWRITTEN: {original_rules}")
        if no_reload:
            print("[REPLACE] Validated replacement installed. Live reload skipped by --no-reload.")
            return 0

        rc = reload_suricata(original_rules, config)
        if rc == 0:
            print("[REPLACE] LIVE: original rules replaced; production validation and reload completed.")
            return 0

        # The file replacement itself was requested explicitly and has already
        # passed Suricata validation.  Do not silently undo it just because the
        # running service could not be reloaded.
        print("[REPLACE] RELOAD FAILED: suricata.rules remains overwritten with the validated tuned rules.", file=sys.stderr)
        return 28

    except Exception as exc:
        print(f"[REPLACE] ERROR: {exc}. Restoring original rules and config...", file=sys.stderr)
        if installed:
            atomic_copy(backup_dir / ("original-" + original_rules.name), original_rules)
        shutil.copy2(backup_dir / config.name, config)
        if threshold_existed:
            atomic_copy(backup_dir / threshold_target.name, threshold_target)
        elif threshold_target.exists():
            threshold_target.unlink()
        print("[REPLACE] Rollback completed; original feed rules were restored.", file=sys.stderr)
        return 27


def migrate_legacy_output_state(output: Path, state_dir: Path) -> None:
    """Move legacy sidecars out of the Suricata rules directory when safe."""
    state_dir.mkdir(parents=True, exist_ok=True)
    moves = [
        (output.with_name("suricata-policy-engine-state.json"), state_dir / "ruleset-state.json"),
        (Path(str(output) + ".report.json"), state_dir / "last-report.json"),
        (output.with_name("suricata-tuned.insights.json"), state_dir / "last-insights.json"),
        (output.with_name("suricata-tuned.telemetry.json"), state_dir / "last-telemetry.json"),
        (output.with_name("suricata-tuned.threshold.config"), state_dir / "suricata-tuned.threshold.config"),
    ]
    for old, new in moves:
        if old.exists() and not new.exists():
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old), str(new))
    legacy_history = output.parent / ".suricata-policy-engine-history"
    new_history = state_dir / "history"
    if legacy_history.exists() and not new_history.exists():
        shutil.move(str(legacy_history), str(new_history))


def cleanup_legacy_output_sidecars(output: Path) -> None:
    """Leave only the tuned rules and single diff report as visible tuner outputs."""
    for path in (
        output.with_name("suricata-policy-engine-state.json"),
        Path(str(output) + ".report.json"),
        output.with_name("suricata-tuned.insights.json"),
        output.with_name("suricata-tuned.telemetry.json"),
        output.with_name("suricata-tuned.threshold.config"),
        output.with_name("suricata-tuned.diff.txt.json"),
        output.parent / ".suricata-policy-engine.lock",
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    args = parse_args()
    replace_original = bool(getattr(args, "replace_original", False))
    final_rc = 0
    if args.deploy and replace_original:
        die("Choose only one production mode: --deploy or --replace-original.")
    output = args.output or args.rules.with_name("suricata-tuned.rules")
    state_dir = default_state_dir()
    report_path = args.report or state_dir / "last-report.json"
    threshold_output = args.threshold_output or state_dir / "suricata-tuned.threshold.config"
    state_file = args.state_file or state_dir / "ruleset-state.json"
    diff_output = args.diff_output or output.with_name("suricata-tuned.diff.txt")
    insights_output = args.insights_output or state_dir / "last-insights.json"
    telemetry_output = args.telemetry_output or state_dir / "last-telemetry.json"
    history_dir = args.history_dir or history.default_history_dir(output)
    migrate_legacy_output_state(output, state_dir)
    if args.history_list:
        rows = history.list_runs(history_dir)
        if not rows:
            print(f"No historical runs in {history_dir}")
            return 0
        for row in rows:
            summary = row.get("summary", {}) or {}
            print(f"{row.get('run_id')}  deployed={row.get('deployed')}  test={row.get('test_passed')}  final={summary.get('final_enabled','?')}  {row.get('created_at','')}")
        return 0
    if args.rollback is not None:
        if not args.no_lock:
            try:
                acquire_process_lock(default_state_dir() / "engine.lock")
            except RuntimeError as exc:
                die(str(exc), 23)
        return rollback_history_run(output, threshold_output, args.suricata_conf, history_dir, args.rollback, args.no_reload)
    if args.preview:
        args.dry_run = True
        args.no_state_update = True
    generation_output = output
    generation_threshold = threshold_output
    if args.deploy or replace_original:
        generation_output = output.with_name(f".{output.name}.candidate.{os.getpid()}")
        generation_threshold = threshold_output.with_name(f".{threshold_output.name}.candidate.{os.getpid()}")

    print("============================================================")
    print(" Suricata Policy Engine")
    print("============================================================")
    print(f"Input rules : {human_path(args.rules)}")
    print(f"Policy      : {human_path(args.policy)}")
    print(f"Output      : {human_path(output)}")

    if not args.rules.exists():
        die(f"Rules file not found: {args.rules}\nRun 'suricata-update' first or use --rules PATH.")
    if not args.policy.exists():
        die(f"Policy file not found: {args.policy}\nUse --policy PATH if it is stored elsewhere.")
    if args.rules.resolve() == output.resolve():
        die("Input and output paths are the same. Use a separate output file for safety.")
    if not args.dry_run and not args.no_lock:
        try:
            acquire_process_lock(default_state_dir() / "engine.lock")
        except RuntimeError as exc:
            die(str(exc), 23)

    print("\n[1/5] Loading policy...")
    policy = core.load_policy(args.policy)
    policy_requires_test = validation_settings(policy)["require_suricata_test"]
    staged_for_validation = False
    if not args.dry_run and not args.deploy and not replace_original and (args.test or policy_requires_test):
        generation_output = output.with_name(f".{output.name}.candidate.{os.getpid()}")
        generation_threshold = threshold_output.with_name(f".{threshold_output.name}.candidate.{os.getpid()}")
        staged_for_validation = True
    print("      OK")

    print("[2/5] Parsing Suricata rules...")
    try:
        rules = core.load_rules(args.rules)
    except ValueError as exc:
        die(str(exc))
    if not rules:
        die("No Suricata rules were parsed from the input file.")
    source_enabled = sum(1 for r in rules.values() if r.source_enabled)
    print(f"      Parsed: {len(rules):,} | Feed enabled before tuning: {source_enabled:,}")
    print("      All rules succefuly parsed")

    print("[3/5] Applying tuning policy + dynamic dependencies...")
    result = apply_policy(rules, policy)
    tracked_audit = audit_tracked_rules(rules, policy, args.tracked_baseline)
    if args.accept_tracked_baseline:
        atomic_write_text(args.tracked_baseline, json.dumps(build_tracked_baseline(rules, policy), indent=2) + "\n")
        tracked_audit = audit_tracked_rules(rules, policy, args.tracked_baseline)
        print(f"      Tracked SID baseline accepted: {human_path(args.tracked_baseline)}")
    final_enabled = sum(1 for r in rules.values() if r.final_enabled)
    print(f"      Final enabled:       {final_enabled:,}")
    print(f"      Flowbits restored:   {len(result['restored_flow']):,}")
    print(f"      Xbits restored:      {len(result['restored_xbit']):,}")

    validation_result = policy_validation_preflight(rules, result, policy, args.suricata_conf)
    if validation_result["failures"]:
        print("\n[VALIDATION] Policy prerequisite failure(s):", file=sys.stderr)
        for failure in validation_result["failures"]:
            print(f"  - {failure}", file=sys.stderr)
        if not args.dry_run:
            return 24

    telemetry_result = None
    if args.eve:
        missing_eve = [p for p in args.eve if not p.exists()]
        if missing_eve:
            die("EVE telemetry file(s) not found: " + ", ".join(str(p) for p in missing_eve), 25)
        try:
            telemetry_result = telemetry_mod.analyze_eve(args.eve, rules, policy)
        except (OSError, ValueError) as exc:
            die(f"Could not analyze EVE telemetry: {exc}", 25)
        print(f"      Telemetry alerts:    {telemetry_result['alert_events']:,}")
        print(f"      Review candidates:   {len(telemetry_result['recommendations']):,} (recommendation-only)")
        if not args.dry_run or args.telemetry_output is not None:
            atomic_write_text(telemetry_output, json.dumps(telemetry_result, indent=2, ensure_ascii=False) + "\n")

    if args.dry_run:
        threshold_result = {"threshold_entries": 0, "suppression_entries": 0,
                            "skipped_rules_with_inline_threshold": 0, "sid_override_entries": 0, "by_category": {}}
    else:
        print("[4/5] Writing tuned rules + threshold/suppress policy...")
        write_tuned_rules(generation_output, rules, args.policy, args.rules)
        threshold_result = write_threshold_config(generation_threshold, rules, policy)
        print(f"      Rules      : {human_path(generation_output)}")
        print(f"      Thresholds : {human_path(generation_threshold)}")

    report = build_report(args, output, threshold_output, rules, result, threshold_result)
    report["validation"] = validation_result
    if telemetry_result is not None:
        report["telemetry"] = telemetry_result
        report["telemetry_output"] = human_path(telemetry_output)
    stats, modes = print_friendly_summary(policy, rules, result, threshold_result)
    print_tracked_audit(tracked_audit, args.tracked_baseline)
    report["policy_mode_summary"] = modes
    report["tracked_sid_integrity"] = tracked_audit

    cur_state = current_state(rules, report["input_sha256"], report["policy_sha256"])
    previous = None
    if state_file.exists():
        try:
            previous = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            previous = None
    diff = compute_diff(previous, cur_state)
    print_diff_summary(diff)

    bundle = insights.insights_bundle(rules, policy, result, tracked_audit, diff, previous)
    print_insights(bundle)
    report["ruleset_diff"] = {k: (len(v) if isinstance(v, list) else v) for k, v in diff.items()}
    report["recommendations"] = bundle["recommendations"]
    report["policy_health"] = bundle["policy_health"]
    report["update_impact"] = bundle["update_impact"]

    if args.insights_output is not None or not args.dry_run:
        insights_output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(insights_output, json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

    if not args.dry_run:
        print("\n[5/5] Writing audit + diff reports...")
        atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        diff_json = None
        if validation_result["settings"]["generate_diff_report"]:
            diff_json = write_diff_reports(diff_output, diff)
        if diff_json is not None:
            print(f"      Diff     : {human_path(diff_output)}")
        else:
            print("      Diff     : disabled by validation.generate_diff_report")
        print("      Internal report/state kept outside the Suricata rules directory.")

    if result["missing_explicit"]:
        print("\nWARNING: Tracked KEEP SIDs missing from this feed: " +
              ", ".join(str(x) for x in sorted(result["missing_explicit"])), file=sys.stderr)
    if result["unknown_enabled"]:
        print(f"\nWARNING: {result['unknown_enabled']} feed-enabled rule(s) did not map to a known category; "
              "their feed state was preserved.", file=sys.stderr)
    if result["missing_flow"]:
        print(f"\nWARNING: {len(result['missing_flow'])} required flowbit name(s) have no setter in this ruleset.", file=sys.stderr)
    if result["missing_xbit"]:
        print(f"\nWARNING: {len(result['missing_xbit'])} required xbit name(s) have no setter in this ruleset.", file=sys.stderr)
    if result.get("ambiguous_flow") or result.get("ambiguous_xbit"):
        print("\nWARNING: toggle-only bit dependencies detected; toggle is not a guaranteed setter and is not auto-restored.", file=sys.stderr)

    print("\n============================================================")
    print(" DONE")
    print(f" Feed enabled before tuning : {report['feed_enabled_before_tuning']:,}")
    print(f" Final enabled              : {report['final_enabled_rules']:,}")
    print(f" Reduced by                 : {report['feed_enabled_before_tuning'] - report['final_enabled_rules']:,}")
    print("============================================================")

    if args.dry_run:
        return 0

    need_test = args.test or args.deploy or replace_original or policy_requires_test
    if need_test:
        rc = run_suricata_test(generation_output, generation_threshold, args.suricata_conf)
        report["validation"]["suricata_test"] = {"required": validation_result["settings"]["require_suricata_test"], "ok": rc == 0, "exit_code": rc}
        if not args.dry_run and report_path.exists():
            atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if rc != 0:
            if args.deploy or replace_original or staged_for_validation:
                generation_output.unlink(missing_ok=True)
                generation_threshold.unlink(missing_ok=True)
            return rc

    if staged_for_validation and not args.deploy:
        atomic_copy(generation_output, output)
        atomic_copy(generation_threshold, threshold_output)
        generation_output.unlink(missing_ok=True)
        generation_threshold.unlink(missing_ok=True)

    if args.deploy:
        rc = deploy_production(generation_output, generation_threshold, args.suricata_conf, args.no_reload,
                               final_output=output, final_threshold_output=threshold_output)
        generation_output.unlink(missing_ok=True)
        generation_threshold.unlink(missing_ok=True)
        if rc != 0:
            return rc

    if replace_original:
        rc = replace_original_production(
            generation_output, generation_threshold, args.rules, output, threshold_output,
            args.suricata_conf, args.no_reload
        )
        generation_output.unlink(missing_ok=True)
        generation_threshold.unlink(missing_ok=True)
        if rc not in (0, 28):
            return rc
        if rc == 28:
            # The validated file overwrite is committed; only the live reload failed.
            # Finish state/history/output cleanup, then surface the non-zero live status.
            final_rc = 28

    # Update comparison baseline only after generation succeeded, and after validation/deploy when requested.
    if not args.no_state_update:
        atomic_write_text(state_file, json.dumps(cur_state, separators=(",", ":")) + "\n")
        print(f"\nState saved for next update diff: {human_path(state_file)}")
    else:
        print("\nState comparison baseline left unchanged (--no-state-update).")

    # Historical snapshots are recorded only for accepted runs. The pre-deploy --test
    # path uses --no-state-update and intentionally does not create a duplicate snapshot.
    if not args.no_state_update:
        try:
            run_dir = history.record_run(
                history_dir, output=output, threshold=threshold_output, policy=args.policy,
                report=report_path,
                diff=(diff_output if validation_result["settings"]["generate_diff_report"] else None),
                insights=insights_output, telemetry=(telemetry_output if telemetry_result is not None else None),
                state=state_file, deployed=bool(args.deploy or replace_original), test_passed=bool(need_test),
                summary={
                    "feed_enabled": report.get("feed_enabled_before_tuning"),
                    "final_enabled": report.get("final_enabled_rules"),
                    "policy_health": (report.get("policy_health") or {}).get("score"),
                    "new_sids": (report.get("update_impact") or {}).get("new_sids", 0),
                }, keep=max(1, args.history_limit),
            )
            print(f"Run history snapshot: {human_path(run_dir)}")
        except Exception as exc:
            print(f"WARNING: could not record run history: {exc}", file=sys.stderr)

    cleanup_legacy_output_sidecars(output)

    if not need_test:
        print("\nNext validation command:")
        print(f"sudo python3 {Path(__file__).name} --test")
    return final_rc


if __name__ == "__main__":
    raise SystemExit(main())
