#!/usr/bin/env python3
"""Deterministic starter profiles for Suricata Policy Engine.

A profile is a reviewed policy preset.  The public profiles deliberately
control the category posture they depend on so switching between profiles does
not inherit a stale mode from the previously selected profile.  Asset inventory
is still kept separate except for the explicit baseline facts requested for the
Balanced/Server presets (Nginx ON, SCADA OFF).
"""
from __future__ import annotations

from copy import deepcopy


_PRESERVE_FEED = {
    "ET_MALWARE", "ET_EXPLOIT", "ET_EXPLOIT_KIT", "ET_PHISHING",
    "ET_ATTACK_RESPONSE", "ET_SHELLCODE", "ET_CNC", "ET_COINMINER",
    "ET_WORM", "ET_CURRENT_EVENTS", "ET_COMPROMISED", "ET_MOBILE_MALWARE",
    "ET_WEB_CLIENT", "ET_FTP", "ET_NETBIOS", "ET_RPC", "ET_SNMP", "ET_SQL",
    "ET_TELNET", "ET_Threatview.io", "GPL_IMAP", "GPL_POP3", "ET_SCAN",
    "ET_DOS",
}

_ASSET_BASED = {"ET_WEB_SPECIFIC_APPS", "ET_WEB_SERVER", "ET_SCADA", "ET_ACTIVEX", "ET_VOIP"}

_CONDITIONAL = {
    "ET_CINS": "enabled_by_default_with_alert_tuning",
    "ET_REMOTE_ACCESS": "organization_policy",
    "ET_USER_AGENTS": "enabled_by_default_with_alert_tuning",
    "ET_JA3": "enabled_by_default",
    "ET_ADWARE_PUP": "enabled_by_default_with_alert_tuning",
    "ET_HUNTING": "enabled_by_default_with_alert_tuning",
    "ET_INFO": "default_disabled_with_allowlist",
    "ET_DYN_DNS": "disabled_by_default",
    "ET_TOR": "disabled_by_default",
    "ET_FILE_SHARING": "disabled_by_default",
    "ET_P2P": "disabled_by_default",
    "ET_CHAT": "disabled_by_default",
    "ET_TA_ABUSED_SERVICES": "disabled_by_default",
    "ET_DNS": "enabled_by_default_with_alert_tuning",
    "ET_DROP": "enabled_by_default_with_alert_tuning",
    "ET_SMTP": "enabled_by_default_with_alert_tuning",
    "ET_TFTP": "default_disabled_with_allowlist",
    "GPL_MISC": "enabled_by_default_with_alert_tuning",
    "ET_GAMES": "disabled_by_default",
    "ET_INAPPROPRIATE": "disabled_by_default",
    "ET_POLICY": "organization_policy_selective",
    "SURICATA": "message_filter",
}

_DISABLED = {"ET_RETIRED", "GPL_ICMP"}

_BASE_DEFAULT_ENABLED = {
    "ET_CINS": True,
    "ET_USER_AGENTS": True,
    "ET_JA3": True,
    "ET_ADWARE_PUP": True,
    "ET_HUNTING": True,
    "ET_INFO": False,
    "ET_DYN_DNS": False,
    "ET_TOR": False,
    "ET_FILE_SHARING": False,
    "ET_P2P": False,
    "ET_CHAT": False,
    "ET_TA_ABUSED_SERVICES": False,
    "ET_DNS": True,
    "ET_DROP": True,
    "ET_SMTP": True,
    "ET_TFTP": False,
    "GPL_MISC": True,
    "ET_GAMES": False,
    "ET_INAPPROPRIATE": False,
}

_ORG_DEFAULTS = {
    "tor": (True, True),
    "file_sharing": (None, False),
    "p2p": (None, False),
    "chat": (None, False),
    "dynamic_dns": (None, False),
    "games": (None, False),
    "inappropriate_content": (None, False),
    # ET POLICY selective families.  These only affect rules matched by the
    # audited selectors; unmatched ET POLICY rules keep their upstream state.
    "anonymizers": (True, True),
    "cloud_storage": (None, False),
    "cleartext_credentials": (True, True),
    "outbound_database": (None, False),
}

_REMOTE_APPS = [
    "anydesk", "centrastage", "comodo_itarian", "connectwise", "dameware",
    "getscreen", "kaseya_pulseway", "microsoft_rdp", "netop", "netsupport",
    "remote_utilities", "screenconnect", "simplehelp", "syncromsp", "teamviewer",
    "teramind", "zoho_assist",
]


def _baseline_category_changes() -> dict[tuple[str, ...], object]:
    changes: dict[tuple[str, ...], object] = {}
    for cat in sorted(_PRESERVE_FEED):
        changes[("categories", cat, "mode")] = "preserve_feed"
    for cat in sorted(_ASSET_BASED):
        changes[("categories", cat, "mode")] = "asset_based"
    for cat, strategy in sorted(_CONDITIONAL.items()):
        changes[("categories", cat, "mode")] = "conditional"
        changes[("categories", cat, "strategy")] = strategy
        if cat in _BASE_DEFAULT_ENABLED:
            changes[("categories", cat, "default_enabled")] = _BASE_DEFAULT_ENABLED[cat]
    for cat in sorted(_DISABLED):
        changes[("categories", cat, "mode")] = "disable"
    return changes


def _baseline_org_changes() -> dict[tuple[str, ...], object]:
    changes: dict[tuple[str, ...], object] = {}
    for key, (prohibited, detection) in _ORG_DEFAULTS.items():
        changes[("organization_policy", key, "prohibited")] = prohibited
        changes[("organization_policy", key, "detection_enabled")] = detection
    changes[("organization_policy", "remote_access", "default_policy")] = "prohibited"
    changes[("organization_policy", "remote_access", "detection_enabled")] = True
    for app in _REMOTE_APPS:
        changes[("organization_policy", "remote_access", "applications", app)] = "prohibited"
    return changes


def _common_baseline() -> dict[tuple[str, ...], object]:
    changes = _baseline_category_changes()
    changes.update(_baseline_org_changes())
    changes.update({
        ("defaults", "preserve_dependencies"): True,
        ("defaults", "dependency_restore", "enabled"): True,
        ("defaults", "dependency_restore", "only_if_required_by_enabled_rule"): True,
        ("defaults", "dependency_restore", "run_after_final_policy_resolution"): True,
        # New/unmapped feed categories keep the vendor/feed state in normal profiles.
        # Strict overrides this below so its high-signal posture is deterministic.
        ("defaults", "disable_unknown_categories"): False,
        ("alert_tuning", "enabled"): True,
    })
    return changes



def _raw_changes() -> dict[tuple[str, ...], object]:
    """Pass the vendor/feed state through unchanged until the operator edits it.

    Raw intentionally disables dependency restoration and generated alert tuning so
    selecting the profile itself does not change Suricata rule state or alert rate.
    Advanced edits made afterwards become the explicit tuning policy.
    """
    c: dict[tuple[str, ...], object] = {}
    all_categories = _PRESERVE_FEED | _ASSET_BASED | set(_CONDITIONAL) | _DISABLED
    for cat in sorted(all_categories):
        c[("categories", cat, "mode")] = "preserve_feed"
    c[("defaults", "disable_unknown_categories")] = False
    c[("defaults", "preserve_dependencies")] = False
    c[("defaults", "dependency_restore", "enabled")] = False
    c[("alert_tuning", "enabled")] = False
    # A raw pass-through must not resurrect an upstream-disabled tracked SID.
    c[("rule_overrides", "ET_INFO", "force_enable_sids")] = []
    c[("rule_overrides", "ET_TFTP", "force_enable_sids")] = []
    return c

def _balanced_changes() -> dict[tuple[str, ...], object]:
    c = _common_baseline()
    c.update({
        ("assets", "web_server", "enabled"): True,
        ("assets", "web_specific_apps", "nginx", "enabled"): True,
        # Preserve the reviewed Balanced posture for the common web-app controls.
        ("assets", "web_specific_apps", "wordpress", "enabled"): False,
        ("assets", "web_specific_apps", "jboss", "enabled"): False,
        ("assets", "web_specific_apps", "exchange", "enabled"): False,
        ("assets", "web_specific_apps", "citrix", "enabled"): False,
        ("assets", "web_specific_apps", "manageengine", "enabled"): False,
        ("assets", "web_specific_apps", "fortinet", "enabled"): False,
        # Explicit user requirement for this profile.
        ("assets", "scada", "enabled"): False,
    })
    return c


def _noisy_changes() -> dict[tuple[str, ...], object]:
    c = _common_baseline()
    # Preserve every feed-enabled category except explicitly retired rules.  This
    # is intentionally broad but still never resurrects rules disabled upstream.
    for cat in sorted(_PRESERVE_FEED | _ASSET_BASED | set(_CONDITIONAL) | {"GPL_ICMP"}):
        if cat != "ET_RETIRED":
            c[("categories", cat, "mode")] = "preserve_feed"
    c[("categories", "ET_RETIRED", "mode")] = "disable"
    for key in _ORG_DEFAULTS:
        c[("organization_policy", key, "detection_enabled")] = True
    c[("organization_policy", "remote_access", "detection_enabled")] = True
    # A profile named Noisy should not silently rate-limit the extra alerts it asks for.
    c[("alert_tuning", "enabled")] = False
    return c


def _strict_changes() -> dict[tuple[str, ...], object]:
    c = _common_baseline()
    # High-signal/core threat families plus protocol attack families.  Broad
    # policy/telemetry/hunting/informational families are explicitly disabled.
    keep = {
        "ET_MALWARE", "ET_EXPLOIT", "ET_EXPLOIT_KIT", "ET_PHISHING",
        "ET_ATTACK_RESPONSE", "ET_SHELLCODE", "ET_CNC", "ET_COINMINER",
        "ET_WORM", "ET_CURRENT_EVENTS", "ET_COMPROMISED", "ET_MOBILE_MALWARE",
        "ET_WEB_CLIENT", "ET_FTP", "ET_NETBIOS", "ET_RPC", "ET_SNMP", "ET_SQL",
        "ET_TELNET", "ET_Threatview.io", "GPL_IMAP", "GPL_POP3", "ET_DOS",
        "ET_DROP",
    }
    asset_keep = {"ET_WEB_SPECIFIC_APPS", "ET_WEB_SERVER", "ET_SCADA", "ET_ACTIVEX", "ET_VOIP"}
    all_categories = _PRESERVE_FEED | _ASSET_BASED | set(_CONDITIONAL) | _DISABLED
    for cat in sorted(all_categories):
        if cat in keep:
            c[("categories", cat, "mode")] = "preserve_feed"
        elif cat in asset_keep:
            c[("categories", cat, "mode")] = "asset_based"
        else:
            c[("categories", cat, "mode")] = "disable"
    # Strict limits detection families, not the truth of the operator's asset inventory.
    # Unknown categories are disabled here rather than inheriting a looser profile's
    # fallback behavior.
    c[("defaults", "disable_unknown_categories")] = True
    c[("alert_tuning", "enabled")] = True
    return c


def _lab_changes() -> dict[tuple[str, ...], object]:
    c = _common_baseline()
    # Useful SOC/SIEM exercise visibility without the near-firehose posture of Noisy.
    c[("categories", "ET_INFO", "strategy")] = "enabled_by_default_with_alert_tuning"
    c[("categories", "ET_INFO", "default_enabled")] = True
    c[("categories", "ET_TFTP", "strategy")] = "enabled_by_default_with_alert_tuning"
    c[("categories", "ET_TFTP", "default_enabled")] = True
    for key in ("tor", "file_sharing", "p2p", "chat", "dynamic_dns", "anonymizers", "cloud_storage", "cleartext_credentials", "outbound_database"):
        c[("organization_policy", key, "detection_enabled")] = True
    c[("organization_policy", "remote_access", "detection_enabled")] = True
    c[("alert_tuning", "enabled")] = True
    return c


def _server_changes() -> dict[tuple[str, ...], object]:
    c = _common_baseline()
    c.update({
        ("assets", "web_server", "enabled"): True,
        ("assets", "web_specific_apps", "nginx", "enabled"): True,
        ("assets", "scada", "enabled"): False,
        ("assets", "activex", "enabled"): False,
        ("assets", "voip", "enabled"): False,
        ("categories", "ET_MOBILE_MALWARE", "mode"): "disable",
        ("categories", "ET_GAMES", "mode"): "disable",
        ("categories", "ET_INAPPROPRIATE", "mode"): "disable",
        ("organization_policy", "file_sharing", "detection_enabled"): False,
        ("organization_policy", "p2p", "detection_enabled"): False,
        ("organization_policy", "chat", "detection_enabled"): False,
        ("organization_policy", "games", "detection_enabled"): False,
        ("organization_policy", "inappropriate_content", "detection_enabled"): False,
        ("organization_policy", "outbound_database", "detection_enabled"): True,
        ("organization_policy", "cleartext_credentials", "detection_enabled"): True,
        ("alert_tuning", "enabled"): True,
    })
    return c


PROFILES = {
    "Raw": {
        "recommended": False,
        "description": "Pass-through profile: keep the current Suricata feed state exactly as delivered. No category tuning, dependency restoration or generated alert tuning is applied until you make manual changes in Advanced Settings.",
        "changes": _raw_changes(),
    },
    "Balanced": {
        "recommended": True,
        "description": "Reviewed day-to-day baseline. Nginx/web-server coverage is ON, SCADA is explicitly OFF, core threat families follow the feed, optional usage-policy families stay controlled, and alert tuning is enabled.",
        "changes": _balanced_changes(),
    },
    "Noisy": {
        "recommended": False,
        "description": "High-visibility / high-volume profile for environments that intentionally want most feed-enabled rules and are willing to accept substantially more alerts. Upstream-disabled and retired rules are still not resurrected.",
        "changes": _noisy_changes(),
    },
    "Strict": {
        "recommended": False,
        "description": "High-signal profile focused on core threat, exploitation and server/protocol attack families. Broad informational, hunting, policy-usage and convenience telemetry categories are disabled unless required as a dependency.",
        "changes": _strict_changes(),
    },
    "Lab / Experimental": {
        "recommended": False,
        "description": "SOC/SIEM practice profile: broader useful telemetry than Balanced, including INFO/TFTP and organization-policy visibility, while retaining alert tuning so a lab is informative without becoming a full firehose.",
        "changes": _lab_changes(),
    },
    "Server": {
        "recommended": False,
        "description": "Server-oriented baseline with web-server + Nginx coverage, SCADA/ActiveX/VoIP disabled by default, client/lifestyle noise reduced, and additional visibility for cleartext credentials and unexpected outbound database activity.",
        "changes": _server_changes(),
    },
}


def profile_names() -> list[str]:
    return list(PROFILES)


def get_profile(name: str) -> dict:
    if name not in PROFILES:
        raise KeyError(name)
    return deepcopy(PROFILES[name])
