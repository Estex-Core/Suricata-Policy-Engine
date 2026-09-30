#!/usr/bin/env python3
"""
Generate Suricata enable.conf / disable.conf from tuning-policy.yaml.

Design goals:
- The YAML is the source of truth; generated SID lists are disposable artifacts.
- Never hard-code flowbits/xbits dependency SIDs in the policy.
- Recompute dependencies from every fresh ruleset.
- Preserve upstream disabled state unless the policy explicitly forces a SID on
  or the SID is required as a dependency.
- Produce an audit report for every run.

Usage:
  python3 generate_suricata_policy.py \
      --policy tuning-policy.yaml \
      --rules suricata.rules \
      --out-dir generated

Requires: PyYAML (python3-yaml / pip install PyYAML)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

try:
    import yaml
except ImportError as exc:
    raise SystemExit(
        "PyYAML is required. Install with: apt install python3-yaml  "
        "or: pip install PyYAML"
    ) from exc


RULE_ACTION_RE = re.compile(
    r"^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+", re.I
)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.I)
REV_RE = re.compile(r"\brev\s*:\s*(\d+)\s*;", re.I)
MSG_RE = re.compile(r'\bmsg\s*:\s*"((?:\\.|[^"\\])*)"\s*;', re.I)
FLOWBITS_RE = re.compile(r"\bflowbits\s*:\s*([^;]+);", re.I)
XBITS_RE = re.compile(r"\bxbits\s*:\s*([^;]+);", re.I)
METADATA_RE = re.compile(r"\bmetadata\s*:\s*([^;]+);", re.I)

FLOW_SETTERS = {"set"}
FLOW_TOGGLERS = {"toggle"}
# Only positive isset creates a dependency on a setter. isnotset intentionally does not.
FLOW_GETTERS = {"isset"}
XBIT_SETTERS = {"set"}
XBIT_TOGGLERS = {"toggle"}
XBIT_GETTERS = {"isset"}


@dataclass(frozen=True, order=True)
class XbitRef:
    """An xbit name plus the Suricata storage scope used by track."""
    name: str
    track: str = "unknown"

    @property
    def scope(self) -> str:
        # ip_src/ip_dst are both stored per host. The direction may legitimately
        # flip between request and response, so dependency compatibility is by
        # storage scope rather than requiring the literal track token to match.
        if self.track in {"ip_src", "ip_dst"}:
            return "host"
        if self.track == "ip_pair":
            return "ip_pair"
        if self.track == "tx":
            return "tx"
        return "unknown"

    def label(self) -> str:
        return f"{self.name}[{self.scope}]" if self.scope != "unknown" else self.name


@dataclass
class Rule:
    sid: int
    rev: int
    msg: str
    raw: str
    source_enabled: bool
    category: Optional[str] = None
    flow_set: Set[str] = field(default_factory=set)
    flow_get: Set[str] = field(default_factory=set)
    # Each group represents one positive flowbits:isset expression. A group may
    # contain alternatives such as {"user1", "user2"} for isset,user1|user2.
    flow_get_groups: List[FrozenSet[str]] = field(default_factory=list)
    flow_toggle: Set[str] = field(default_factory=set)
    xbit_set: Set[str] = field(default_factory=set)
    xbit_get: Set[str] = field(default_factory=set)
    xbit_set_refs: Set[XbitRef] = field(default_factory=set)
    xbit_get_refs: Set[XbitRef] = field(default_factory=set)
    xbit_toggle_refs: Set[XbitRef] = field(default_factory=set)
    metadata: Dict[str, List[str]] = field(default_factory=dict)
    asset_match_asset: Optional[str] = None
    asset_match_score: int = 0
    asset_match_evidence: List[str] = field(default_factory=list)
    asset_match_status: str = "not_evaluated"
    asset_match_candidates: List[dict] = field(default_factory=list)
    asset_review_candidate: bool = False
    initial_enabled: bool = False
    final_enabled: bool = False
    reason: str = ""
    restored_dependency_types: Set[str] = field(default_factory=set)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_rule_records(path: Path) -> Iterable[Tuple[str, bool]]:
    """Yield logical one-line rule records and whether they were enabled upstream."""
    buf = ""
    buf_enabled = True

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for physical in f:
            line = physical.rstrip("\n")
            if not buf:
                stripped = line.lstrip()
                enabled = True
                candidate = stripped
                if stripped.startswith("#"):
                    enabled = False
                    candidate = stripped[1:].lstrip()
                if not RULE_ACTION_RE.match(candidate):
                    continue
                buf_enabled = enabled
                buf = candidate
            else:
                buf += " " + line.strip()

            if buf.rstrip().endswith("\\"):
                buf = buf.rstrip()[:-1].rstrip()
                continue

            yield buf.strip(), buf_enabled
            buf = ""

    if buf:
        yield buf.strip(), buf_enabled


def _split_flowbit_names(value: str) -> FrozenSet[str]:
    """Return the alternatives in a flowbits name expression (e.g. a|b)."""
    return frozenset(part.strip() for part in value.split("|") if part.strip())


def split_rule_options(raw: str) -> List[Tuple[str, Optional[str]]]:
    """Tokenize Suricata rule options without interpreting text inside quotes.

    Regex-searching an entire rule for ``sid:``, ``flowbits:`` and similar tokens is
    subtly unsafe because those byte sequences can legally occur inside msg/content/
    pcre strings.  This scanner splits only on semicolons outside double-quoted text,
    then treats the first colon of each token as the key/value delimiter.
    """
    start = raw.find("(")
    end = raw.rfind(")")
    if start < 0 or end <= start:
        return []
    body = raw[start + 1:end]
    tokens: List[str] = []
    buf: List[str] = []
    quoted = False
    escaped = False
    quoted_key: Optional[str] = None
    for idx, ch in enumerate(body):
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and quoted:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            if not quoted:
                # Remember which option owns this quoted value.  PCRE patterns
                # legally use literal double quotes inside character classes, e.g.
                # pcre:"/^["']?post/Ri";.  Those inner quotes must not terminate
                # the option value.
                prefix = "".join(buf).strip()
                quoted_key = prefix.split(":", 1)[0].strip().lower() if ":" in prefix else None
                quoted = True
            elif quoted_key == "pcre":
                # In a quoted PCRE value, only a quote that is followed by the
                # option terminator is the closing quote.
                j = idx + 1
                while j < len(body) and body[j].isspace():
                    j += 1
                if j >= len(body) or body[j] == ";":
                    quoted = False
                    quoted_key = None
            else:
                quoted = False
                quoted_key = None
            buf.append(ch)
            continue
        if ch == ";" and not quoted:
            token = "".join(buf).strip()
            if token:
                tokens.append(token)
            buf = []
            quoted_key = None
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        tokens.append(tail)

    out: List[Tuple[str, Optional[str]]] = []
    for token in tokens:
        if ":" in token:
            key, value = token.split(":", 1)
            out.append((key.strip().lower(), value.strip()))
        else:
            out.append((token.strip().lower(), None))
    return out


def option_values(raw: str, key: str) -> List[str]:
    wanted = key.lower()
    return [value for name, value in split_rule_options(raw) if name == wanted and value is not None]


def _unquote_option(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_flowbit_options(raw: str) -> Tuple[Set[str], Set[str], List[FrozenSet[str]]]:
    setters: Set[str] = set()
    getters: Set[str] = set()
    getter_groups: List[FrozenSet[str]] = []
    for value in option_values(raw, "flowbits"):
        parts = [p.strip() for p in value.strip().split(",")]
        if not parts:
            continue
        op = parts[0].lower()
        if op == "noalert" or len(parts) < 2:
            continue
        names = _split_flowbit_names(parts[1])
        if not names:
            continue
        if op in FLOW_SETTERS:
            # OR is meaningful on positive checks. If a feed uses multiple setter
            # names, retain them independently rather than inventing a dependency.
            setters.update(names)
        if op in FLOW_GETTERS:
            getters.update(names)
            getter_groups.append(names)
    return setters, getters, getter_groups


def parse_flowbit_toggles(raw: str) -> Set[str]:
    out: Set[str] = set()
    for value in option_values(raw, "flowbits"):
        parts = [p.strip() for p in value.strip().split(",")]
        if len(parts) >= 2 and parts[0].lower() in FLOW_TOGGLERS:
            out.update(_split_flowbit_names(parts[1]))
    return out


def _xbit_track(parts: List[str]) -> str:
    for token in parts[2:]:
        m = re.fullmatch(r"track\s+(ip_src|ip_dst|ip_pair|tx)", token.strip(), re.I)
        if m:
            return m.group(1).lower()
    return "unknown"


def parse_xbit_options(raw: str) -> Tuple[Set[str], Set[str], Set[XbitRef], Set[XbitRef]]:
    setters: Set[str] = set()
    getters: Set[str] = set()
    setter_refs: Set[XbitRef] = set()
    getter_refs: Set[XbitRef] = set()
    for value in option_values(raw, "xbits"):
        parts = [p.strip() for p in value.strip().split(",")]
        if not parts:
            continue
        op = parts[0].lower()
        if op == "noalert" or len(parts) < 2:
            continue
        name = parts[1]
        if not name:
            continue
        ref = XbitRef(name=name, track=_xbit_track(parts))
        if op in XBIT_SETTERS:
            setters.add(name)
            setter_refs.add(ref)
        if op in XBIT_GETTERS:
            getters.add(name)
            getter_refs.add(ref)
    return setters, getters, setter_refs, getter_refs


def parse_xbit_toggles(raw: str) -> Set[XbitRef]:
    out: Set[XbitRef] = set()
    for value in option_values(raw, "xbits"):
        parts = [p.strip() for p in value.strip().split(",")]
        if len(parts) >= 2 and parts[0].lower() in XBIT_TOGGLERS and parts[1]:
            out.add(XbitRef(name=parts[1], track=_xbit_track(parts)))
    return out


def parse_bit_options(raw: str, keyword: str) -> Tuple[Set[str], Set[str]]:
    """Backward-compatible helper used by callers/tests that only need names."""
    if keyword == "flowbits":
        setters, getters, _groups = parse_flowbit_options(raw)
        return setters, getters
    setters, getters, _set_refs, _get_refs = parse_xbit_options(raw)
    return setters, getters


def parse_metadata(raw: str) -> Dict[str, List[str]]:
    """Parse Suricata metadata into a case-normalized multi-value mapping."""
    out: Dict[str, List[str]] = defaultdict(list)
    for value in option_values(raw, "metadata"):
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split(None, 1)
            key = parts[0].strip().lower()
            metadata_value = parts[1].strip() if len(parts) > 1 else ""
            if metadata_value and metadata_value not in out[key]:
                out[key].append(metadata_value)
    return dict(out)


def rule_logic_sha256_v1(raw: str) -> str:
    """Legacy v1 baseline hash, retained only for baseline compatibility."""
    text = REV_RE.sub("", raw)
    text = METADATA_RE.sub("", text)
    text = re.sub(r"\breference\s*:[^;]+;", "", text, flags=re.I)
    text = re.sub(r"\bclasstype\s*:[^;]+;", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_logic_sha256(raw: str) -> str:
    """Fingerprint detection semantics while excluding identity/descriptive churn."""
    start = raw.find("(")
    end = raw.rfind(")")
    if start < 0 or end <= start:
        normalized = re.sub(r"\s+", " ", raw).strip()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    # Keep the full rule header/action because direction, addresses, ports, protocol
    # and action are detection semantics. Reconstruct options after dropping fields
    # that are identity/revision/documentation rather than packet-match logic.
    header = re.sub(r"\s+", " ", raw[:start]).strip()
    ignored = {"sid", "rev", "msg", "metadata", "reference", "classtype"}
    option_parts: List[str] = []
    for key, value in split_rule_options(raw):
        if key in ignored:
            continue
        token = key if value is None else f"{key}:{value}"
        option_parts.append(re.sub(r"\s+", " ", token).strip())
    text = f"{header} (" + ";".join(option_parts) + ";)"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_raw_sha256(raw: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", raw).strip().encode("utf-8")).hexdigest()


def load_rules(path: Path) -> Dict[int, Rule]:
    rules: Dict[int, Rule] = {}
    for raw, enabled in iter_rule_records(path):
        sid_values = option_values(raw, "sid")
        if not sid_values:
            continue
        try:
            sid = int(sid_values[-1].strip())
        except ValueError:
            continue
        if sid in rules:
            raise ValueError(f"Duplicate SID in input ruleset: {sid}")
        rev_values = option_values(raw, "rev")
        try:
            rev = int(rev_values[-1].strip()) if rev_values else 0
        except ValueError:
            rev = 0
        msg_values = option_values(raw, "msg")
        msg = _unquote_option(msg_values[-1]) if msg_values else ""
        flow_set, flow_get, flow_get_groups = parse_flowbit_options(raw)
        flow_toggle = parse_flowbit_toggles(raw)
        xbit_set, xbit_get, xbit_set_refs, xbit_get_refs = parse_xbit_options(raw)
        xbit_toggle_refs = parse_xbit_toggles(raw)
        metadata = parse_metadata(raw)
        rules[sid] = Rule(
            sid=sid,
            rev=rev,
            msg=msg,
            raw=raw,
            source_enabled=enabled,
            flow_set=flow_set,
            flow_get=flow_get,
            flow_get_groups=flow_get_groups,
            flow_toggle=flow_toggle,
            xbit_set=xbit_set,
            xbit_get=xbit_get,
            xbit_set_refs=xbit_set_refs,
            xbit_get_refs=xbit_get_refs,
            xbit_toggle_refs=xbit_toggle_refs,
            metadata=metadata,
        )
    return rules


VALID_MODES = {"preserve_feed", "keep", "disable", "asset_based", "conditional"}
VALID_STRATEGIES = {
    "selective", "enabled_by_default", "enabled_by_default_with_alert_tuning",
    "disabled_by_default", "organization_policy", "organization_policy_selective",
    "default_disabled_with_allowlist", "message_filter",
}


def _validate_regex(pattern: object, location: str) -> None:
    text = str(pattern).strip()
    if not text:
        raise ValueError(f"Empty regex at {location}")
    # These patterns are syntactically valid but operationally dangerous in a
    # policy selector because they match essentially everything.  Reject the
    # common accidental forms before tuning a feed.
    if text in {".*", "^.*$", ".+", "^.+$"}:
        raise ValueError(f"Over-broad regex at {location}: {pattern!r}")
    try:
        re.compile(text, re.I)
    except re.error as exc:
        raise ValueError(f"Invalid regex at {location}: {pattern!r}: {exc}") from exc


def validate_policy(data: dict) -> dict:
    """Validate policy structure that directly affects decision correctness.

    This intentionally focuses on engine-bearing fields (modes, strategies, regexes,
    asset thresholds and tracked/force SID relationships) so bad policy edits fail
    before any rules are tuned.
    """
    categories = data.get("categories")
    if not isinstance(categories, dict):
        raise ValueError("Invalid policy YAML: missing top-level 'categories' mapping")
    for name, cfg in categories.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"Category {name} must be a mapping")
        mode = cfg.get("mode")
        if mode not in VALID_MODES:
            raise ValueError(f"Category {name} has invalid mode: {mode!r}")
        strategy = cfg.get("strategy")
        if mode == "conditional" and strategy not in VALID_STRATEGIES:
            raise ValueError(f"Category {name} has invalid conditional strategy: {strategy!r}")
        filters = cfg.get("message_filter", {}) or {}
        patterns = filters.get("disable_regex", []) or []
        if isinstance(patterns, str):
            patterns = [patterns]
        for idx, pattern in enumerate(patterns):
            _validate_regex(pattern, f"categories.{name}.message_filter.disable_regex[{idx}]")

    apps = ((data.get("assets", {}) or {}).get("web_specific_apps", {}) or {})
    if not isinstance(apps, dict):
        raise ValueError("assets.web_specific_apps must be a mapping")
    for name, raw_cfg in apps.items():
        cfg = normalize_asset_cfg(name, raw_cfg)
        if not 0 <= cfg["review_threshold"] <= 100 or not 0 <= cfg["match_threshold"] <= 100:
            raise ValueError(f"Asset {name} thresholds must be between 0 and 100")
        if cfg["review_threshold"] > cfg["match_threshold"]:
            raise ValueError(f"Asset {name} review_threshold cannot exceed match_threshold")
        for idx, pattern in enumerate(cfg["msg_regex"]):
            _validate_regex(pattern, f"assets.web_specific_apps.{name}.msg_regex[{idx}]")
        for key, accepted in (cfg.get("metadata") or {}).items():
            values = accepted if isinstance(accepted, list) else [accepted]
            for idx, value in enumerate(values):
                if str(value).startswith("re:"):
                    _validate_regex(str(value)[3:], f"assets.web_specific_apps.{name}.metadata.{key}[{idx}]")

    databases = ((data.get("assets", {}) or {}).get("database_products", {}) or {})
    if not isinstance(databases, dict):
        raise ValueError("assets.database_products must be a mapping")
    for name, raw_cfg in databases.items():
        cfg = normalize_asset_cfg(name, raw_cfg)
        if not 0 <= cfg["review_threshold"] <= 100 or not 0 <= cfg["match_threshold"] <= 100:
            raise ValueError(f"Database asset {name} thresholds must be between 0 and 100")
        if cfg["review_threshold"] > cfg["match_threshold"]:
            raise ValueError(f"Database asset {name} review_threshold cannot exceed match_threshold")
        for idx, pattern in enumerate(cfg["msg_regex"]):
            _validate_regex(pattern, f"assets.database_products.{name}.msg_regex[{idx}]")
        for key, accepted in (cfg.get("metadata") or {}).items():
            values = accepted if isinstance(accepted, list) else [accepted]
            for idx, value in enumerate(values):
                if str(value).startswith("re:"):
                    _validate_regex(str(value)[3:], f"assets.database_products.{name}.metadata.{key}[{idx}]")

    feed_products = ((data.get("assets", {}) or {}).get("feed_products", {}) or {})
    if not isinstance(feed_products, dict):
        raise ValueError("assets.feed_products must be a mapping")
    for name, raw_cfg in feed_products.items():
        if not isinstance(raw_cfg, dict):
            raise ValueError(f"assets.feed_products.{name} must be a mapping")
        values = raw_cfg.get("metadata_values", []) or []
        if isinstance(values, str):
            values = [values]
        if not values:
            raise ValueError(f"assets.feed_products.{name} requires at least one metadata_values entry")
        if any(not str(v).strip() for v in values):
            raise ValueError(f"assets.feed_products.{name} contains an empty metadata value")

    org = data.get("organization_policy", {}) or {}
    org_selectors = data.get("organization_policy_selectors", []) or []
    if not isinstance(org_selectors, list):
        raise ValueError("organization_policy_selectors must be a list")
    seen_selector_names = set()
    for sidx, selector in enumerate(org_selectors):
        if not isinstance(selector, dict):
            raise ValueError(f"organization_policy_selectors[{sidx}] must be a mapping")
        name = str(selector.get("name") or "").strip()
        if not name:
            raise ValueError(f"organization_policy_selectors[{sidx}] requires a name")
        if name in seen_selector_names:
            raise ValueError(f"Duplicate organization policy selector name: {name}")
        seen_selector_names.add(name)
        org_key = str(selector.get("organization_key") or "").strip()
        if not org_key or org_key not in org:
            raise ValueError(
                f"organization_policy_selectors[{sidx}] references unknown organization key: {org_key!r}"
            )
        patterns = selector.get("msg_regex", []) or []
        if isinstance(patterns, str):
            patterns = [patterns]
        contains = selector.get("msg_contains", []) or []
        if isinstance(contains, str):
            contains = [contains]
        if any(not str(value).strip() for value in contains):
            raise ValueError(f"organization_policy_selectors[{sidx}].msg_contains contains an empty value")
        metadata = selector.get("metadata", {}) or {}
        if not patterns and not contains and not metadata:
            raise ValueError(f"organization_policy_selectors[{sidx}] has no matching criteria")
        for pidx, pattern in enumerate(patterns):
            _validate_regex(pattern, f"organization_policy_selectors[{sidx}].msg_regex[{pidx}]")
        for key, accepted in metadata.items():
            values = accepted if isinstance(accepted, list) else [accepted]
            for vidx, value in enumerate(values):
                if str(value).startswith("re:"):
                    _validate_regex(
                        str(value)[3:],
                        f"organization_policy_selectors[{sidx}].metadata.{key}[{vidx}]",
                    )

    for cat, cfg in (data.get("rule_overrides", {}) or {}).items():
        if not isinstance(cfg, dict):
            raise ValueError(f"rule_overrides.{cat} must be a mapping")
        selectors = cfg.get("semantic_keep", []) or []
        if isinstance(selectors, dict):
            selectors = [selectors]
        seen_semantic_names = set()
        for sidx, selector in enumerate(selectors):
            if not isinstance(selector, dict):
                raise ValueError(f"rule_overrides.{cat}.semantic_keep[{sidx}] must be a mapping")
            selector_name = str(selector.get("name") or "").strip()
            if not selector_name:
                raise ValueError(f"rule_overrides.{cat}.semantic_keep[{sidx}] requires a name")
            if selector_name in seen_semantic_names:
                raise ValueError(f"Duplicate semantic selector name in {cat}: {selector_name}")
            seen_semantic_names.add(selector_name)
            patterns = selector.get("msg_regex", []) or []
            if isinstance(patterns, str):
                patterns = [patterns]
            contains = selector.get("msg_contains", []) or []
            if isinstance(contains, str):
                contains = [contains]
            if any(not str(value).strip() for value in contains):
                raise ValueError(f"rule_overrides.{cat}.semantic_keep[{sidx}].msg_contains contains an empty value")
            metadata = selector.get("metadata", {}) or {}
            if not patterns and not contains and not metadata:
                raise ValueError(f"rule_overrides.{cat}.semantic_keep[{sidx}] has no matching criteria")
            for pidx, pattern in enumerate(patterns):
                _validate_regex(pattern, f"rule_overrides.{cat}.semantic_keep[{sidx}].msg_regex[{pidx}]")
            for key, accepted in metadata.items():
                values = accepted if isinstance(accepted, list) else [accepted]
                for vidx, value in enumerate(values):
                    if str(value).startswith("re:"):
                        _validate_regex(str(value)[3:], f"rule_overrides.{cat}.semantic_keep[{sidx}].metadata.{key}[{vidx}]")
        tracked = [int(x) for x in (cfg.get("tracked_keep_sids", cfg.get("explicit_keep_sids", [])) or [])]
        if len(tracked) != len(set(tracked)):
            raise ValueError(f"rule_overrides.{cat}.tracked_keep_sids contains duplicates")
        forced = {int(x) for x in (cfg.get("force_enable_sids", []) or [])}
        unknown_forced = forced - set(tracked)
        if unknown_forced:
            raise ValueError(
                f"rule_overrides.{cat}.force_enable_sids must also be tracked; untracked: {sorted(unknown_forced)}"
            )
    return data


def load_policy(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Invalid policy YAML: top level must be a mapping")
    return validate_policy(data)


def et_prefix_from_key(key: str) -> Optional[str]:
    if not key.startswith("ET_"):
        return None
    return "ET " + key[3:]


def map_category(msg: str, policy: dict) -> Optional[str]:
    categories = policy.get("categories", {})

    if msg == "SURICATA" or msg.startswith("SURICATA "):
        return "SURICATA" if "SURICATA" in categories else None

    if msg.startswith("GPL "):
        mapping = policy.get("gpl_category_mapping", {}) or {}
        # Longest names first so WEB_SPECIFIC_APPS beats WEB_SERVER-like prefixes.
        for raw_name in sorted(mapping, key=len, reverse=True):
            prefix = f"GPL {raw_name}"
            if msg == prefix or msg.startswith(prefix + " "):
                return mapping[raw_name]
        return None

    # Match known ET policy category prefixes; longest first prevents ET WEB_SERVER
    # from accidentally winning over a longer future category.
    candidates: List[Tuple[str, str]] = []
    for key in categories:
        prefix = et_prefix_from_key(key)
        if prefix:
            candidates.append((prefix, key))
    for prefix, key in sorted(candidates, key=lambda x: len(x[0]), reverse=True):
        if msg == prefix or msg.startswith(prefix + " "):
            return key
    return None


def asset_value(policy: dict, path: Tuple[str, ...], default: bool = False) -> bool:
    obj = policy.get("assets", {})
    for part in path:
        if not isinstance(obj, dict) or part not in obj:
            return default
        obj = obj[part]
    if isinstance(obj, dict) and "enabled" in obj:
        return bool(obj["enabled"])
    return bool(obj) if isinstance(obj, bool) else default


ORG_POLICY_CATEGORY_MAP = {
    "ET_TOR": "tor",
    "ET_FILE_SHARING": "file_sharing",
    "ET_P2P": "p2p",
    "ET_CHAT": "chat",
    "ET_DYN_DNS": "dynamic_dns",
    "ET_GAMES": "games",
    "ET_INAPPROPRIATE": "inappropriate_content",
    "ET_REMOTE_ACCESS": "remote_access",
}


def org_detection_enabled(policy: dict, key: str, default: bool = False) -> bool:
    obj = (policy.get("organization_policy", {}) or {}).get(key, {})
    if isinstance(obj, dict):
        return bool(obj.get("detection_enabled", default))
    return default


def _norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def _matches_configured_value(value: str, configured) -> bool:
    """Exact normalized match by default; a value prefixed with re: is a regex."""
    for item in configured or []:
        item = str(item)
        if item.startswith("re:"):
            if re.search(item[3:], value, re.I):
                return True
        elif _norm_token(value) == _norm_token(item):
            return True
    return False


def normalize_asset_cfg(name: str, value) -> dict:
    """Normalize legacy booleans and richer metadata-first asset definitions."""
    default_alias = str(name).replace("_", " ").replace("-", " ")
    if isinstance(value, bool):
        return {
            "enabled": value,
            "aliases": [default_alias],
            "metadata": {},
            "msg_regex": [],
            "match_threshold": 80,
            "review_threshold": 50,
        }
    if isinstance(value, dict):
        aliases = value.get("aliases", value.get("match_terms", [])) or []
        if isinstance(aliases, str):
            aliases = [aliases]
        if not aliases:
            aliases = [default_alias]
        regexes = value.get("msg_regex", []) or []
        if isinstance(regexes, str):
            regexes = [regexes]
        return {
            "enabled": bool(value.get("enabled", False)),
            "aliases": [str(x) for x in aliases],
            "metadata": value.get("metadata", {}) or {},
            "msg_regex": [str(x) for x in regexes],
            "match_threshold": int(value.get("match_threshold", 80)),
            "review_threshold": int(value.get("review_threshold", 50)),
        }
    return normalize_asset_cfg(name, False)


def _web_app_remainder(msg: str) -> str:
    for prefix in ("ET WEB_SPECIFIC_APPS ", "GPL WEB_SPECIFIC_APPS "):
        if msg.startswith(prefix):
            return msg[len(prefix):]
    return msg


def _score_web_asset(rule: Rule, app_name: str, raw_cfg) -> dict:
    """Return evidence for one configured web asset, independent of enable state."""
    cfg = normalize_asset_cfg(app_name, raw_cfg)
    remainder = _web_app_remainder(rule.msg or "")
    score = 0
    evidence: List[str] = []

    # Product-identifying metadata is authoritative evidence when available.
    for key, accepted in (cfg.get("metadata") or {}).items():
        values = rule.metadata.get(str(key).lower(), [])
        for value in values:
            if _matches_configured_value(value, accepted if isinstance(accepted, list) else [accepted]):
                score = max(score, 100)
                evidence.append(f"metadata:{key}={value}")
                break

    # Message fallback is deliberately anchored to the category-specific body.
    for alias in cfg.get("aliases", []):
        if re.match(r"^" + re.escape(alias) + r"(?:\b|[-\s_/])", remainder, re.I):
            score = max(score, 90)
            evidence.append(f"msg-prefix:{alias}")
            break

    for pattern in cfg.get("msg_regex", []):
        if re.search(pattern, remainder, re.I):
            score = max(score, 85)
            evidence.append(f"msg-regex:{pattern}")
            break

    # Context may strengthen an existing product identification but never creates it.
    if score and any(_norm_token(v) == "server" for v in rule.metadata.get("attack_target", [])):
        score = min(100, score + 5)
        evidence.append("metadata:attack_target=Server")

    return {
        "asset": str(app_name),
        "enabled": bool(cfg["enabled"]),
        "score": score,
        "evidence": evidence,
        "match_threshold": cfg["match_threshold"],
        "review_threshold": cfg["review_threshold"],
    }


def _score_feed_product_assets(rule: Rule, policy: dict) -> List[dict]:
    """Exact affected_product fallbacks discovered from the operator's current feed.

    Curated asset matchers remain authoritative. These candidates are consulted
    only when no curated matcher produced evidence, preventing a generic product
    override from fighting a reviewed matcher for the same rule.
    """
    products = ((policy.get("assets", {}) or {}).get("feed_products", {}) or {})
    affected = rule.metadata.get("affected_product", [])
    out: List[dict] = []
    for name, raw in products.items():
        if not isinstance(raw, dict):
            continue
        accepted = raw.get("metadata_values", []) or []
        if isinstance(accepted, str):
            accepted = [accepted]
        matches = [v for v in affected if _matches_configured_value(v, accepted)]
        if not matches:
            continue
        out.append({
            "asset": f"feed:{name}",
            "enabled": bool(raw.get("enabled", False)),
            "score": 100,
            "evidence": [f"metadata:affected_product={v}" for v in matches],
            "match_threshold": 100,
            "review_threshold": 100,
        })
    return out


def web_specific_app_decision(rule: Rule, policy: dict) -> Tuple[bool, str]:
    """Evidence-driven asset decision with explicit ambiguity handling.

    All configured assets are scored, including disabled assets.  A disabled asset
    can therefore be identified explicitly instead of disappearing from the trace.
    Tied strongest candidates are REVIEW_REQUIRED rather than depending on YAML
    iteration order.  A unique, threshold-qualified enabled asset preserves the
    upstream feed state; a unique disabled asset stays disabled.
    """
    apps = ((policy.get("assets", {}) or {}).get("web_specific_apps", {}) or {})
    candidates = [_score_web_asset(rule, name, raw) for name, raw in apps.items()]
    candidates = [c for c in candidates if c["score"] > 0]
    if not candidates:
        candidates = _score_feed_product_assets(rule, policy)
    candidates.sort(key=lambda c: (-c["score"], c["asset"]))
    rule.asset_match_candidates = candidates[:10]
    rule.asset_review_candidate = False
    rule.asset_match_asset = None
    rule.asset_match_score = 0
    rule.asset_match_evidence = []

    if not candidates:
        rule.asset_match_status = "no_match"
        return False, "asset_web_app_no_match"

    top_score = candidates[0]["score"]
    tied = [c for c in candidates if c["score"] == top_score]
    if len(tied) > 1:
        rule.asset_match_status = "ambiguous"
        rule.asset_review_candidate = True
        rule.asset_match_score = top_score
        rule.asset_match_evidence = [
            f"candidate:{c['asset']}:enabled={str(c['enabled']).lower()}:score={c['score']}"
            for c in tied
        ]
        return False, "asset_review:ambiguous:" + "|".join(c["asset"] for c in tied)

    best = candidates[0]
    rule.asset_match_asset = best["asset"]
    rule.asset_match_score = best["score"]
    rule.asset_match_evidence = list(best["evidence"])

    if best["score"] >= best["match_threshold"]:
        if best["enabled"]:
            rule.asset_match_status = "matched_enabled"
            return rule.source_enabled, f"asset_match_enabled:{best['asset']}:score={best['score']}"
        rule.asset_match_status = "matched_disabled"
        return False, f"asset_match_disabled:{best['asset']}:score={best['score']}"

    if best["score"] >= best["review_threshold"]:
        rule.asset_match_status = "review_required"
        rule.asset_review_candidate = True
        return False, f"asset_review:{best['asset']}:score={best['score']}"

    rule.asset_match_status = "weak_match"
    return False, f"asset_web_app_weak_match:{best['asset']}:score={best['score']}"


def _database_remainder(msg: str) -> str:
    for prefix in ("ET SQL ", "ETPRO SQL ", "GPL SQL "):
        if msg.startswith(prefix):
            return msg[len(prefix):]
    return msg


def _score_database_asset(rule: Rule, asset_name: str, raw_cfg) -> dict:
    """Score a database product using the same evidence hierarchy as web assets."""
    cfg = normalize_asset_cfg(asset_name, raw_cfg)
    remainder = _database_remainder(rule.msg or "")
    score = 0
    evidence: List[str] = []

    for key, accepted in (cfg.get("metadata") or {}).items():
        values = rule.metadata.get(str(key).lower(), [])
        for value in values:
            if _matches_configured_value(value, accepted if isinstance(accepted, list) else [accepted]):
                score = max(score, 100)
                evidence.append(f"metadata:{key}={value}")
                break

    for alias in cfg.get("aliases", []):
        if re.match(r"^" + re.escape(alias) + r"(?:\b|[-\s_/])", remainder, re.I):
            score = max(score, 90)
            evidence.append(f"msg-prefix:{alias}")
            break

    for pattern in cfg.get("msg_regex", []):
        if re.search(pattern, remainder, re.I):
            score = max(score, 85)
            evidence.append(f"msg-regex:{pattern}")
            break

    return {
        "asset": str(asset_name),
        "enabled": bool(cfg["enabled"]),
        "score": score,
        "evidence": evidence,
        "match_threshold": cfg["match_threshold"],
        "review_threshold": cfg["review_threshold"],
    }


def database_product_decision(rule: Rule, policy: dict) -> Tuple[bool, str]:
    """Resolve ET_SQL against explicitly configured database products.

    ET_SQL remains PRESERVE_FEED in the shipped profiles.  This function is used
    only when an operator explicitly changes ET_SQL to ASSET_BASED.
    """
    products = ((policy.get("assets", {}) or {}).get("database_products", {}) or {})
    candidates = [_score_database_asset(rule, name, raw) for name, raw in products.items()]
    candidates = [c for c in candidates if c["score"] > 0]
    if not candidates:
        candidates = _score_feed_product_assets(rule, policy)
    candidates.sort(key=lambda c: (-c["score"], c["asset"]))
    rule.asset_match_candidates = candidates[:10]
    rule.asset_review_candidate = False
    rule.asset_match_asset = None
    rule.asset_match_score = 0
    rule.asset_match_evidence = []

    if not candidates:
        rule.asset_match_status = "no_match"
        return False, "asset_database_no_match"

    top_score = candidates[0]["score"]
    tied = [c for c in candidates if c["score"] == top_score]
    if len(tied) > 1:
        rule.asset_match_status = "ambiguous"
        rule.asset_review_candidate = True
        rule.asset_match_score = top_score
        rule.asset_match_evidence = [
            f"candidate:{c['asset']}:enabled={str(c['enabled']).lower()}:score={c['score']}"
            for c in tied
        ]
        return False, "asset_review:ambiguous_database:" + "|".join(c["asset"] for c in tied)

    best = candidates[0]
    rule.asset_match_asset = best["asset"]
    rule.asset_match_score = best["score"]
    rule.asset_match_evidence = list(best["evidence"])
    if best["score"] >= best["match_threshold"]:
        if best["enabled"]:
            rule.asset_match_status = "matched_enabled"
            return rule.source_enabled, f"asset_database_enabled:{best['asset']}:score={best['score']}"
        rule.asset_match_status = "matched_disabled"
        return False, f"asset_database_disabled:{best['asset']}:score={best['score']}"
    if best["score"] >= best["review_threshold"]:
        rule.asset_match_status = "review_required"
        rule.asset_review_candidate = True
        return False, f"asset_review:database:{best['asset']}:score={best['score']}"
    rule.asset_match_status = "weak_match"
    return False, f"asset_database_weak_match:{best['asset']}:score={best['score']}"


def selector_matches(rule: Rule, selector: dict) -> bool:
    """Semantic selector used before SID-level exceptions."""
    if not isinstance(selector, dict):
        return False
    patterns = selector.get("msg_regex", []) or []
    if isinstance(patterns, str):
        patterns = [patterns]
    if patterns and not any(re.search(str(p), rule.msg or "", re.I) for p in patterns):
        return False
    contains = selector.get("msg_contains", []) or []
    if isinstance(contains, str):
        contains = [contains]
    if contains and not any(str(x).lower() in (rule.msg or "").lower() for x in contains):
        return False
    md = selector.get("metadata", {}) or {}
    for key, accepted in md.items():
        values = rule.metadata.get(str(key).lower(), [])
        if not any(_matches_configured_value(v, accepted) for v in values):
            return False
    return bool(patterns or contains or md)



def organization_policy_selective_decision(rule: Rule, policy: dict) -> Tuple[bool, str]:
    """Apply Organization Policy only to reviewed semantic families.

    ET POLICY is intentionally heterogeneous.  Pure usage-policy detections can be
    controlled by the organization, while unmatched/security-oriented signatures
    preserve the feed state.  If overlapping selectors request conflicting
    detection states, preserve upstream and make the ambiguity visible.
    """
    matches: List[Tuple[str, str, bool]] = []
    for selector in policy.get("organization_policy_selectors", []) or []:
        if selector_matches(rule, selector):
            key = str(selector.get("organization_key") or "")
            name = str(selector.get("name") or key)
            detect = org_detection_enabled(policy, key, False)
            matches.append((name, key, detect))

    if not matches:
        return rule.source_enabled, "organization_policy_selective_preserve_upstream"

    states = {detect for _name, _key, detect in matches}
    if len(states) > 1:
        keys = "|".join(sorted({key for _name, key, _detect in matches}))
        return rule.source_enabled, f"organization_policy_selector_ambiguous_preserve_upstream:{keys}"

    detect = matches[0][2]
    keys = "|".join(sorted({key for _name, key, _detect in matches}))
    if detect:
        return rule.source_enabled, f"organization_policy_selective_enabled:{keys}"
    return False, f"organization_policy_selective_disabled:{keys}"


def base_policy_decision(rule: Rule, policy: dict, unresolved_selective: Counter) -> Tuple[bool, str]:
    if not rule.category:
        disable_unknown = bool((policy.get("defaults", {}) or {}).get("disable_unknown_categories", False))
        return (False, "unknown_category_disabled") if disable_unknown else (rule.source_enabled, "unknown_category_preserve_upstream")

    cfg = (policy.get("categories", {}) or {}).get(rule.category, {}) or {}
    mode = cfg.get("mode")

    if mode in {"preserve_feed", "keep"}:
        return rule.source_enabled, "preserve_feed_state"

    if mode == "disable":
        return False, "category_disable"

    if mode == "asset_based":
        if rule.category == "ET_WEB_SPECIFIC_APPS":
            return web_specific_app_decision(rule, policy)
        if rule.category == "ET_SQL":
            return database_product_decision(rule, policy)
        mapping = {
            "ET_WEB_SERVER": ("web_server",),
            "ET_SCADA": ("scada",),
            "ET_ACTIVEX": ("activex",),
            "ET_VOIP": ("voip",),
        }
        path = mapping.get(rule.category)
        enabled = asset_value(policy, path, cfg.get("default_enabled", False)) if path else bool(cfg.get("default_enabled", False))
        return (rule.source_enabled, "asset_enabled") if enabled else (False, "asset_disabled")

    if mode == "conditional":
        strategy = cfg.get("strategy", "selective")

        if strategy in {"enabled_by_default", "enabled_by_default_with_alert_tuning"}:
            return rule.source_enabled, strategy

        if strategy == "disabled_by_default":
            org_key = ORG_POLICY_CATEGORY_MAP.get(rule.category)
            enabled = org_detection_enabled(policy, org_key, cfg.get("default_enabled", False)) if org_key else bool(cfg.get("default_enabled", False))
            return (rule.source_enabled, "conditional_org_enabled") if enabled else (False, "conditional_disabled_by_default")

        if strategy == "organization_policy":
            org_key = ORG_POLICY_CATEGORY_MAP.get(rule.category)
            if org_key:
                enabled = org_detection_enabled(policy, org_key, cfg.get("default_enabled", False))
                reason = f"organization_policy_{org_key}_enabled" if enabled else f"organization_policy_{org_key}_disabled"
                return (rule.source_enabled, reason) if enabled else (False, reason)
            return rule.source_enabled, "organization_policy_preserve_upstream"

        if strategy == "organization_policy_selective":
            return organization_policy_selective_decision(rule, policy)

        if strategy == "default_disabled_with_allowlist":
            return False, "conditional_default_disabled"

        if strategy == "message_filter":
            filters = cfg.get("message_filter", {}) or {}
            msg = rule.msg or ""
            for term in filters.get("disable_contains", []) or []:
                if str(term).lower() in msg.lower():
                    return False, f"message_filter_disable:{term}"
            for pattern in filters.get("disable_regex", []) or []:
                if re.search(str(pattern), msg, re.I):
                    return False, f"message_filter_disable_regex:{pattern}"
            return rule.source_enabled, "message_filter_preserve_feed"

        if strategy == "selective":
            unresolved_selective[rule.category] += 1
            # Conservative fallback: do not silently delete an unreviewed security rule.
            return rule.source_enabled, "selective_preserve_upstream_pending_review"

        # Unknown strategy: fail-safe preserve current upstream state and report it.
        unresolved_selective[f"{rule.category}:unknown_strategy:{strategy}"] += 1
        return rule.source_enabled, "unknown_strategy_preserve_upstream"

    # Unknown mode: preserve upstream and report through reason.
    unresolved_selective[f"{rule.category}:unknown_mode:{mode}"] += 1
    return rule.source_enabled, "unknown_mode_preserve_upstream"


def apply_explicit_overrides(rules: Dict[int, Rule], policy: dict) -> dict:
    """Apply semantic keep selectors first, then tracked SID guardrails.

    Tracked SIDs do not resurrect feed-disabled rules unless force_enable is explicitly configured.
    This preserves vendor retirement/disable decisions while still detecting drift.
    """
    tracked: Set[int] = set()
    tracked_enabled: Set[int] = set()
    missing: List[int] = []
    semantic_kept: Set[int] = set()
    tracked_feed_disabled: Set[int] = set()

    for cat, cfg in (policy.get("rule_overrides", {}) or {}).items():
        selectors = cfg.get("semantic_keep", []) or []
        if isinstance(selectors, dict):
            selectors = [selectors]
        for rule in rules.values():
            if rule.category != cat or not rule.source_enabled:
                continue
            if any(selector_matches(rule, selector) for selector in selectors):
                rule.initial_enabled = True
                rule.reason += "+semantic_keep"
                semantic_kept.add(rule.sid)

        tracked_sids = cfg.get("tracked_keep_sids", cfg.get("explicit_keep_sids", [])) or []
        force_sids = {int(x) for x in (cfg.get("force_enable_sids", []) or [])}
        for sid in tracked_sids:
            sid = int(sid)
            if sid not in rules:
                missing.append(sid)
                continue
            tracked.add(sid)
            rule = rules[sid]
            if rule.source_enabled or sid in force_sids:
                rule.initial_enabled = True
                rule.reason += "+tracked_keep"
                tracked_enabled.add(sid)
            else:
                tracked_feed_disabled.add(sid)
                rule.reason += "+tracked_feed_disabled"

    return {
        "tracked_keep_sids": tracked,
        "tracked_enabled_sids": tracked_enabled,
        "missing_tracked_sids": missing,
        "semantic_keep_sids": semantic_kept,
        "tracked_feed_disabled_sids": tracked_feed_disabled,
    }



def dependency_indexes(rules: Dict[int, Rule]):
    """Legacy name-only indexes used by the TUI/explorer."""
    flow_setters: Dict[str, Set[int]] = defaultdict(set)
    xbit_setters: Dict[str, Set[int]] = defaultdict(set)
    for r in rules.values():
        for name in r.flow_set:
            flow_setters[name].add(r.sid)
        for name in r.xbit_set:
            xbit_setters[name].add(r.sid)
    return flow_setters, xbit_setters


def xbit_dependency_index(rules: Dict[int, Rule]) -> Dict[Tuple[str, str], Set[int]]:
    """Index xbit setters by (name, storage scope)."""
    out: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    for r in rules.values():
        refs = r.xbit_set_refs or {XbitRef(name=n) for n in r.xbit_set}
        for ref in refs:
            out[(ref.name, ref.scope)].add(r.sid)
    return out


def toggle_dependency_indexes(rules: Dict[int, Rule]):
    flow: Dict[str, Set[int]] = defaultdict(set)
    xbit: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    for r in rules.values():
        for name in r.flow_toggle:
            flow[name].add(r.sid)
        for ref in r.xbit_toggle_refs:
            xbit[(ref.name, ref.scope)].add(r.sid)
    return flow, xbit


def _flow_requirement_groups(rule: Rule) -> List[FrozenSet[str]]:
    if rule.flow_get_groups:
        return rule.flow_get_groups
    return [frozenset({name}) for name in sorted(rule.flow_get)]


def _xbit_requirements(rule: Rule) -> Set[XbitRef]:
    return rule.xbit_get_refs or {XbitRef(name=n) for n in rule.xbit_get}


def _dependency_cycles(adjacency: Dict[int, Set[int]]) -> List[List[int]]:
    """Return strongly connected SID components that form dependency cycles."""
    index = 0
    stack: List[int] = []
    on_stack: Set[int] = set()
    indexes: Dict[int, int] = {}
    low: Dict[int, int] = {}
    cycles: List[List[int]] = []

    def visit(v: int) -> None:
        nonlocal index
        indexes[v] = low[v] = index
        index += 1
        stack.append(v); on_stack.add(v)
        for w in adjacency.get(v, set()):
            if w not in indexes:
                visit(w); low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], indexes[w])
        if low[v] == indexes[v]:
            comp: List[int] = []
            while True:
                w = stack.pop(); on_stack.remove(w); comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in adjacency.get(comp[0], set())):
                cycles.append(sorted(comp))

    all_nodes = set(adjacency)
    for vals in adjacency.values():
        all_nodes.update(vals)
    for node in sorted(all_nodes):
        if node not in indexes:
            visit(node)
    return sorted(cycles, key=lambda x: (x[0], len(x)))


def build_dependency_graph(rules: Dict[int, Rule], policy: Optional[dict] = None) -> dict:
    """Build a static SID dependency graph with evidence for every requirement.

    Edges point consumer SID -> deterministic producer SID.  Toggle-only candidates
    are reported separately because toggle does not guarantee the bit becomes set.
    """
    dep_types = {"flowbits", "xbits"}
    if policy is not None:
        defaults = policy.get("defaults", {}) or {}
        dep_types = set(defaults.get("dependency_types", ["flowbits", "xbits"]) or [])
    flow_setters, _ = dependency_indexes(rules)
    xbit_setters = xbit_dependency_index(rules)
    flow_togglers, xbit_togglers = toggle_dependency_indexes(rules)
    edges: List[dict] = []
    requirements: List[dict] = []
    adjacency: Dict[int, Set[int]] = defaultdict(set)

    for sid in sorted(rules):
        rule = rules[sid]
        if "flowbits" in dep_types:
            for group in _flow_requirement_groups(rule):
                producers = sorted({p for name in group for p in flow_setters.get(name, set())})
                toggles = sorted({p for name in group for p in flow_togglers.get(name, set())})
                label = "|".join(sorted(group))
                status = "resolved" if producers else ("toggle_only" if toggles else "missing")
                requirements.append({
                    "consumer_sid": sid, "type": "flowbits", "requirement": label,
                    "alternatives": sorted(group), "producer_sids": producers,
                    "toggle_sids": toggles, "status": status,
                })
                for producer in producers:
                    adjacency[sid].add(producer)
                    edges.append({"consumer_sid": sid, "producer_sid": producer,
                                  "type": "flowbits", "requirement": label})
        if "xbits" in dep_types:
            for ref in sorted(_xbit_requirements(rule)):
                key = (ref.name, ref.scope)
                producers = sorted(xbit_setters.get(key, set()))
                toggles = sorted(xbit_togglers.get(key, set()))
                status = "resolved" if producers else ("toggle_only" if toggles else "missing")
                requirements.append({
                    "consumer_sid": sid, "type": "xbits", "requirement": ref.label(),
                    "scope": ref.scope, "producer_sids": producers,
                    "toggle_sids": toggles, "status": status,
                })
                for producer in producers:
                    adjacency[sid].add(producer)
                    edges.append({"consumer_sid": sid, "producer_sid": producer,
                                  "type": "xbits", "requirement": ref.label()})
    return {
        "edges": edges,
        "requirements": requirements,
        "cycles": _dependency_cycles(adjacency),
        "edge_count": len(edges),
        "requirement_count": len(requirements),
    }


def resolve_dependencies(rules: Dict[int, Rule], policy: dict) -> Tuple[Set[int], Set[int], Set[str], Set[str], Set[str], Set[str]]:
    """Restore dependencies by traversing the explicit SID dependency graph.

    The public tuple return stays backward compatible.  Detailed graph/edge trace is
    available through ``build_dependency_graph`` and ``dependency_resolution_trace``.
    """
    defaults = policy.get("defaults", {}) or {}
    dep_cfg = defaults.get("dependency_restore", {}) or {}
    if not defaults.get("preserve_dependencies", True) or not dep_cfg.get("enabled", True):
        for r in rules.values():
            r.final_enabled = r.initial_enabled
            r.restored_dependency_types.clear()
        return set(), set(), set(), set(), set(), set()

    graph = build_dependency_graph(rules, policy)
    req_by_consumer: Dict[int, List[dict]] = defaultdict(list)
    for req in graph["requirements"]:
        req_by_consumer[int(req["consumer_sid"])].append(req)

    for r in rules.values():
        r.final_enabled = r.initial_enabled
        r.restored_dependency_types.clear()

    restored_flow: Set[int] = set()
    restored_xbit: Set[int] = set()
    queue = [sid for sid, r in sorted(rules.items()) if r.final_enabled]
    seen_consumers: Set[int] = set()
    reachable_requirements: List[dict] = []
    restoration_edges: List[dict] = []

    while queue:
        consumer_sid = queue.pop(0)
        if consumer_sid in seen_consumers:
            continue
        seen_consumers.add(consumer_sid)
        for req in req_by_consumer.get(consumer_sid, []):
            reachable_requirements.append(req)
            for producer_sid in req["producer_sids"]:
                producer = rules.get(producer_sid)
                if producer is None:
                    continue
                restoration_edges.append({
                    "consumer_sid": consumer_sid, "producer_sid": producer_sid,
                    "type": req["type"], "requirement": req["requirement"],
                    "restored": not producer.final_enabled,
                })
                if not producer.final_enabled:
                    producer.final_enabled = True
                    producer.restored_dependency_types.add(req["type"])
                    if req["type"] == "flowbits":
                        restored_flow.add(producer_sid)
                    else:
                        restored_xbit.add(producer_sid)
                    queue.append(producer_sid)

    missing_flow: Set[str] = set()
    missing_xbit: Set[str] = set()
    ambiguous_flow: Set[str] = set()
    ambiguous_xbit: Set[str] = set()
    for req in reachable_requirements:
        if req["status"] == "missing":
            (missing_flow if req["type"] == "flowbits" else missing_xbit).add(req["requirement"])
        elif req["status"] == "toggle_only":
            (ambiguous_flow if req["type"] == "flowbits" else ambiguous_xbit).add(req["requirement"])

    # Attach the latest resolution trace to the function for callers that need
    # explainability without changing the long-standing return signature.
    resolve_dependencies.last_trace = {
        **graph,
        "reachable_consumer_sids": sorted(seen_consumers),
        "reachable_requirement_count": len(reachable_requirements),
        "restoration_edges": restoration_edges,
        "restored_flow_sids": sorted(restored_flow),
        "restored_xbit_sids": sorted(restored_xbit),
    }
    return restored_flow, restored_xbit, missing_flow, missing_xbit, ambiguous_flow, ambiguous_xbit


resolve_dependencies.last_trace = {}


def write_sid_conf(path: Path, title: str, sids: Iterable[int], meta: dict):
    sids = sorted(set(int(s) for s in sids))
    with path.open("w", encoding="utf-8") as f:
        f.write(f"# {title}\n")
        f.write("# AUTO-GENERATED. DO NOT EDIT. Edit tuning-policy.yaml instead.\n")
        f.write(f"# Generated: {meta['generated_at']}\n")
        f.write(f"# Rules SHA256: {meta['rules_sha256']}\n")
        f.write(f"# Policy SHA256: {meta['policy_sha256']}\n")
        f.write(f"# SID count: {len(sids)}\n\n")
        for sid in sids:
            f.write(f"{sid}\n")


def write_report_md(path: Path, report: dict):
    lines = [
        "# Suricata Tuning Generator Report",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Parsed rules: **{report['total_rules']}**",
        f"- Upstream enabled rules: **{report['source_enabled_rules']}**",
        f"- Policy-disabled SIDs written to `disable.conf`: **{report['disable_conf_sids']}**",
        f"- SIDs written to `enable.conf`: **{report['enable_conf_sids']}**",
        f"- Estimated final enabled rules after policy + dependency restore: **{report['final_enabled_rules']}**",
        f"- Flowbit dependency SIDs restored: **{report['dependency_restore']['flowbits_sids']}**",
        f"- Xbit dependency SIDs restored: **{report['dependency_restore']['xbits_sids']}**",
        f"- Missing tracked KEEP SIDs: **{len(report['missing_tracked_keep_sids'])}**",
        f"- Unmapped/unknown category rules: **{report['unknown_category_rules']}** (upstream enabled: **{report['unknown_category_enabled_rules']}**)",
        "",
        "## Categories by final enabled rule count",
        "",
    ]
    for cat, count in sorted(report["final_enabled_by_category"].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- `{cat}`: {count}")

    lines += ["", "## Selective categories still pending deeper rule-level review", ""]
    if report["selective_pending"]:
        for cat, count in sorted(report["selective_pending"].items()):
            lines.append(f"- `{cat}`: {count} rules preserved upstream for now")
    else:
        lines.append("- None")

    lines += ["", "## Dependency checks", ""]
    if report["dependency_restore"]["missing_flowbit_names"]:
        lines.append("- Flowbit names referenced with no setter in this ruleset:")
        for name in report["dependency_restore"]["missing_flowbit_names"]:
            lines.append(f"  - `{name}`")
    else:
        lines.append("- No missing flowbit setter names found.")
    if report["dependency_restore"]["missing_xbit_names"]:
        lines.append("- Xbit names referenced with no setter in this ruleset:")
        for name in report["dependency_restore"]["missing_xbit_names"]:
            lines.append(f"  - `{name}`")
    else:
        lines.append("- No missing xbit setter names found.")
    if report["dependency_restore"].get("ambiguous_flowbit_toggle_names"):
        lines.append("- Flowbit dependencies with toggle-only producers (review; not auto-restored):")
        for name in report["dependency_restore"]["ambiguous_flowbit_toggle_names"]:
            lines.append(f"  - `{name}`")
    if report["dependency_restore"].get("ambiguous_xbit_toggle_names"):
        lines.append("- Xbit dependencies with toggle-only producers (review; not auto-restored):")
        for name in report["dependency_restore"]["ambiguous_xbit_toggle_names"]:
            lines.append(f"  - `{name}`")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Suricata enable/disable policy files")
    ap.add_argument("--policy", required=True, type=Path, help="tuning-policy.yaml")
    ap.add_argument("--rules", required=True, type=Path, help="fresh full Suricata ruleset")
    ap.add_argument("--out-dir", required=True, type=Path, help="output directory")
    ap.add_argument(
        "--fail-on-selective",
        action="store_true",
        help="exit non-zero if a category with strategy=selective remains unreviewed",
    )
    args = ap.parse_args()

    policy = load_policy(args.policy)
    rules = load_rules(args.rules)
    if not rules:
        raise SystemExit("No Suricata rules parsed from input")

    unresolved_selective: Counter = Counter()
    unknown_count = 0
    unknown_enabled_count = 0

    for r in rules.values():
        r.category = map_category(r.msg, policy)
        if r.category is None:
            unknown_count += 1
            if r.source_enabled:
                unknown_enabled_count += 1
        enabled, reason = base_policy_decision(r, policy, unresolved_selective)
        r.initial_enabled = enabled
        r.reason = reason

    overrides = apply_explicit_overrides(rules, policy)
    explicit_keep_sids = overrides["tracked_enabled_sids"] | overrides["semantic_keep_sids"]
    missing_explicit = overrides["missing_tracked_sids"]

    # Keep generator artifacts derived from the exact resolved policy state instead
    # of maintaining a second reason-code allowlist. Any feed-enabled rule that is
    # inactive after base policy + semantic/SID overrides is intentionally disabled
    # by policy and belongs in disable.conf. Upstream-disabled rules are left alone.
    policy_disabled_sids = {
        r.sid for r in rules.values()
        if r.source_enabled and not r.initial_enabled
    }

    restored_flow, restored_xbit, missing_flow, missing_xbit, ambiguous_flow, ambiguous_xbit = resolve_dependencies(rules, policy)

    validation = policy.get("validation", {}) or {}
    if validation.get("check_flowbit_dependencies", True) and missing_flow:
        print("ERROR: unresolved flowbit dependency groups: " + ", ".join(sorted(missing_flow)), file=sys.stderr)
        return 3
    if validation.get("check_xbit_dependencies", True) and missing_xbit:
        print("ERROR: unresolved xbit dependencies: " + ", ".join(sorted(missing_xbit)), file=sys.stderr)
        return 3

    restored_all = restored_flow | restored_xbit
    # enable.conf contains explicit policy exceptions and dynamically discovered deps.
    enable_sids = explicit_keep_sids | restored_all

    # If a dependency SID is policy-disabled it stays in disable.conf and is then
    # re-enabled by enable.conf. Suricata-Update applies disable before enable.
    # Explicit KEEP SIDs were excluded from disable.conf by the initial override.

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    meta = {
        "generated_at": now,
        "rules_sha256": sha256_file(args.rules),
        "policy_sha256": sha256_file(args.policy),
    }

    write_sid_conf(out / "disable.conf", "Suricata disable filters", policy_disabled_sids, meta)
    write_sid_conf(out / "enable.conf", "Suricata enable filters", enable_sids, meta)

    final_by_cat = Counter((r.category or "UNMAPPED") for r in rules.values() if r.final_enabled)
    source_enabled = sum(1 for r in rules.values() if r.source_enabled)
    final_enabled = sum(1 for r in rules.values() if r.final_enabled)

    report = {
        **meta,
        "total_rules": len(rules),
        "source_enabled_rules": source_enabled,
        "disable_conf_sids": len(policy_disabled_sids),
        "enable_conf_sids": len(enable_sids),
        "final_enabled_rules": final_enabled,
        "unknown_category_rules": unknown_count,
        "unknown_category_enabled_rules": unknown_enabled_count,
        "missing_tracked_keep_sids": sorted(missing_explicit),
        "semantic_keep_sids": len(overrides["semantic_keep_sids"]),
        "tracked_feed_disabled_sids": sorted(overrides["tracked_feed_disabled_sids"]),
        "selective_pending": dict(sorted(unresolved_selective.items())),
        "dependency_restore": {
            "flowbits_sids": len(restored_flow),
            "xbits_sids": len(restored_xbit),
            "flowbits_sid_list": sorted(restored_flow),
            "xbits_sid_list": sorted(restored_xbit),
            "missing_flowbit_names": sorted(missing_flow),
            "missing_xbit_names": sorted(missing_xbit),
            "ambiguous_flowbit_toggle_names": sorted(ambiguous_flow),
            "ambiguous_xbit_toggle_names": sorted(ambiguous_xbit),
        },
        "final_enabled_by_category": dict(sorted(final_by_cat.items())),
    }

    (out / "generator-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_report_md(out / "generator-report.md", report)

    with (out / "rule-decisions.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "sid", "rev", "category", "source_enabled", "initial_enabled",
            "final_enabled", "dependency_restore", "reason", "asset", "asset_score", "asset_evidence", "msg"
        ])
        for r in sorted(rules.values(), key=lambda x: x.sid):
            w.writerow([
                r.sid,
                r.rev,
                r.category or "UNMAPPED",
                int(r.source_enabled),
                int(r.initial_enabled),
                int(r.final_enabled),
                "+".join(sorted(r.restored_dependency_types)),
                r.reason,
                r.asset_match_asset or "",
                r.asset_match_score,
                " | ".join(r.asset_match_evidence),
                r.msg,
            ])

    print(f"Parsed rules:           {len(rules)}")
    print(f"Source enabled:         {source_enabled}")
    print(f"disable.conf SIDs:      {len(policy_disabled_sids)}")
    print(f"enable.conf SIDs:       {len(enable_sids)}")
    print(f"Flowbit deps restored:  {len(restored_flow)}")
    if ambiguous_flow:
        print(f"Flowbit toggle-only deps: {len(ambiguous_flow)} (review; not auto-restored)")
    if ambiguous_xbit:
        print(f"Xbit toggle-only deps:   {len(ambiguous_xbit)} (review; not auto-restored)")
    print(f"Xbit deps restored:     {len(restored_xbit)}")
    print(f"Final enabled estimate: {final_enabled}")
    print(f"Unknown categories:     {unknown_count} (enabled={unknown_enabled_count})")
    print(f"Output:                 {out}")

    if missing_explicit:
        print(f"WARNING: missing tracked KEEP SIDs: {missing_explicit}", file=sys.stderr)
    if unresolved_selective:
        print(
            "WARNING: selective categories preserved upstream pending deeper review: "
            + ", ".join(f"{k}={v}" for k, v in sorted(unresolved_selective.items())),
            file=sys.stderr,
        )
        if args.fail_on_selective:
            return 2
    if unknown_count:
        print(
            f"WARNING: {unknown_count} rules did not map to a known category; upstream state preserved.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
