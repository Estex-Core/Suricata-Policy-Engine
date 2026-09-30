"""Resolve editable runtime policy/baseline paths for source and pipx installs."""
from __future__ import annotations

import os
import shutil
import hashlib
from copy import deepcopy

import yaml
from importlib import resources
from pathlib import Path

APP_DIR_NAME = "suricata-policy-engine"


def _config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_DIR_NAME


def default_state_dir() -> Path:
    """Return the private runtime-state directory.

    User-visible rule artifacts stay beside suricata.rules; internal reports,
    threshold staging, comparison state, history and locks live here instead.
    """
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    path = root / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def _materialize_packaged(name: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = resources.files("suricata_policy_engine_data").joinpath(name)
    with resources.as_file(src) as real:
        shutil.copy2(real, dest)
    return dest


def _deep_merge_missing(current: dict, defaults: dict) -> bool:
    """Add schema keys introduced by newer packaged policies without overwriting user values."""
    changed = False
    for key, value in defaults.items():
        if key not in current:
            current[key] = deepcopy(value)
            changed = True
        elif isinstance(current.get(key), dict) and isinstance(value, dict):
            changed = _deep_merge_missing(current[key], value) or changed
    return changed


def _upgrade_managed_policy(path: Path) -> Path:
    """Schema-merge a persisted ~/.config policy with the packaged policy.

    pipx upgrades intentionally preserve the user's runtime policy.  New engine
    releases can add categories/assets/organization-policy fields, so an older
    runtime policy must receive only the *missing* schema keys before the TUI or
    profiles try to edit them.  Existing operator values are never overwritten.
    """
    try:
        current = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(current, dict):
            return path
        src = resources.files("suricata_policy_engine_data").joinpath("tuning-policy.yaml")
        with resources.as_file(src) as real:
            defaults_text = real.read_text(encoding="utf-8")
        defaults = yaml.safe_load(defaults_text)
        if not isinstance(defaults, dict):
            return path
        if not _deep_merge_missing(current, defaults):
            return path
        digest = hashlib.sha256(defaults_text.encode("utf-8")).hexdigest()[:12]
        backup = path.with_name(path.name + f".pre-schema-{digest}.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        tmp = path.with_name(path.name + ".schema.tmp")
        tmp.write_text(yaml.safe_dump(current, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8")
        # Parse the written file before replacing the live policy.
        parsed = yaml.safe_load(tmp.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("migrated policy did not parse as a mapping")
        tmp.replace(path)
    except Exception:
        # Startup must not destroy a user's policy.  The normal loader will show
        # a useful parse/validation error if the existing file itself is broken.
        try:
            path.with_name(path.name + ".schema.tmp").unlink(missing_ok=True)
        except Exception:
            pass
    return path


def default_policy_path(script_dir: Path) -> Path:
    env = os.environ.get("SURICATA_POLICY_ENGINE_POLICY") or os.environ.get("SURICATA_TUNER_POLICY")
    if env:
        return Path(env).expanduser()
    for adjacent in (script_dir / "tuning-policy.yaml", script_dir.parent / "tuning-policy.yaml"):
        if adjacent.exists():
            return adjacent
    user = _config_home() / "tuning-policy.yaml"
    if user.exists():
        return _upgrade_managed_policy(user)
    return _materialize_packaged("tuning-policy.yaml", user)


def default_baseline_path(script_dir: Path) -> Path:
    env = os.environ.get("SURICATA_POLICY_ENGINE_BASELINE") or os.environ.get("SURICATA_TUNER_BASELINE")
    if env:
        return Path(env).expanduser()
    adjacent = script_dir / "tracked-rules-baseline.json"
    if adjacent.exists():
        return adjacent
    user = _config_home() / "tracked-rules-baseline.json"
    if user.exists():
        return user
    return _materialize_packaged("tracked-rules-baseline.json", user)
