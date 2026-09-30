#!/usr/bin/env python3
"""Terminal UI for Suricata Policy Engine.

Main menu is intentionally small:
    Dashboard
    Policy Editor
    Tune My Rules
    Check SIDs

The TUI is local/offline, uses Python's standard curses module, and delegates
rule processing to the existing tune_rules.py core.
"""
from __future__ import annotations

import argparse
import curses
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass, field
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from runtime_paths import default_policy_path, default_baseline_path, default_state_dir

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = default_policy_path(SCRIPT_DIR)
DEFAULT_RULES = Path("/var/lib/suricata/rules/suricata.rules")
DEFAULT_OUTPUT = Path("/var/lib/suricata/rules/suricata-tuned.rules")
DEFAULT_CONF = Path("/etc/suricata/suricata.yaml")
DEFAULT_TRACKED_BASELINE = default_baseline_path(SCRIPT_DIR)

try:
    import yaml
except Exception:
    yaml = None


@dataclass
class Setting:
    label: str
    path: tuple[str, ...]
    kind: str = "bool"  # bool | tri | enum | int | text | str_list | int_list
    options: tuple[Any, ...] = ()
    help: str = ""
    value_labels: dict[Any, str] = field(default_factory=dict)
    value_help: dict[Any, str] = field(default_factory=dict)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TUI for Suricata Policy Engine")
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--suricata-conf", type=Path, default=DEFAULT_CONF)
    p.add_argument("--check", action="store_true", help="Run a non-interactive environment check")
    p.add_argument("--explain-sid", type=int, default=None,
                   help="Explain one SID non-interactively using the current feed and policy")
    return p.parse_args()


def load_policy(path: Path) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required. Install package: python3-yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Policy YAML did not parse as a mapping")
    return data


def get_path(data: Any, path: tuple[Any, ...], default=None):
    cur = data
    for part in path:
        if isinstance(part, int):
            if not isinstance(cur, list) or part >= len(cur):
                return default
            cur = cur[part]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
    return cur


def _yaml_scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    # JSON double-quoted strings are valid YAML and preserve backslashes safely.
    return json.dumps(str(value), ensure_ascii=False)


def _mapping_key_match(line: str):
    return re.match(r"^(\s*)([^#\n][^:\n]*?):(?:\s*(.*?))?(\s+#.*)?(\r?\n)?$", line)


def _find_mapping_key(lines: list[str], key_path: tuple[str, ...]):
    """Return (index, indent, regex_match) for a mapping path."""
    stack: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        m = _mapping_key_match(line)
        if not m:
            continue
        indent = len(m.group(1).replace("\t", "    "))
        key = m.group(2).strip().strip('"\'')
        while stack and stack[-1][0] >= indent:
            stack.pop()
        current = tuple(k for _, k in stack) + (key,)
        if current == key_path:
            return idx, indent, m
        raw = (m.group(3) or "").strip()
        if raw == "" or raw in {"|", ">"}:
            stack.append((indent, key))
    return None


def _block_end(lines: list[str], start: int, indent: int) -> int:
    """Find first line after a mapping value block."""
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped:
            i += 1
            continue
        leading = len(raw) - len(raw.lstrip(" "))
        # A same/lower-indented comment usually belongs to the next field/section; preserve it.
        if stripped.startswith("#"):
            if leading <= indent:
                break
            i += 1
            continue
        if leading <= indent:
            break
        i += 1
    return i


def _find_parent_end(lines: list[str], parent_path: tuple[str, ...]):
    found = _find_mapping_key(lines, parent_path)
    if not found:
        return None
    idx, indent, _ = found
    return _block_end(lines, idx, indent), indent


def _patch_yaml_lines(lines: list[str], key_path: tuple[str, ...], value: Any) -> list[str]:
    """Patch one YAML mapping value in an in-memory line buffer."""
    found = _find_mapping_key(lines, key_path)

    def rendered(base_indent: int, key_text: str, render_value: Any, comment: str = "") -> list[str]:
        pad = " " * base_indent
        if isinstance(render_value, (list, dict)):
            if render_value == []:
                return [f"{pad}{key_text}: []{comment}\n"]
            if render_value == {}:
                return [f"{pad}{key_text}: {{}}{comment}\n"]
            body = yaml.safe_dump(render_value, sort_keys=False, allow_unicode=True, width=4096).rstrip("\n").splitlines()
            out = [f"{pad}{key_text}:{comment}\n"]
            child_pad = " " * (base_indent + 2)
            out.extend(child_pad + row + "\n" for row in body)
            return out
        return [f"{pad}{key_text}: {_yaml_scalar(render_value)}{comment}\n"]

    if found:
        idx, indent, m = found
        key_text = m.group(2)
        comment = m.group(4) or ""
        old_raw = (m.group(3) or "").strip()
        if isinstance(value, (list, dict)) or old_raw == "":
            end = _block_end(lines, idx, indent)
            lines[idx:end] = rendered(indent, key_text, value, comment)
        else:
            newline = m.group(5) or "\n"
            lines[idx] = f"{m.group(1)}{key_text}: {_yaml_scalar(value)}{comment}{newline}"
        return lines

    if len(key_path) < 2:
        raise RuntimeError(f"Cannot insert top-level key: {'.'.join(key_path)}")
    ancestor = None
    ancestor_len = 0
    for depth in range(len(key_path) - 1, 0, -1):
        candidate = _find_parent_end(lines, key_path[:depth])
        if candidate:
            ancestor = candidate
            ancestor_len = depth
            break
    if not ancestor:
        raise RuntimeError(f"Could not find YAML ancestor for: {'.'.join(key_path)}")
    insert_at, parent_indent = ancestor
    missing = list(key_path[ancestor_len:])
    nested: Any = value
    for part in reversed(missing[1:]):
        nested = {part: nested}
    child_indent = parent_indent + 2
    lines[insert_at:insert_at] = rendered(child_indent, missing[0], nested)
    return lines


def patch_yaml_value(path: Path, key_path: tuple[str, ...], value: Any) -> None:
    """Patch one YAML value atomically while preserving unrelated comments/layout."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    _patch_yaml_lines(lines, key_path, value)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(lines), encoding="utf-8")
    load_policy(tmp)
    tmp.replace(path)

def apply_policy_changes(
    path: Path,
    changes: dict[tuple[str, ...], Any],
    *,
    source: str = "manual",
) -> Path:
    """Apply policy edits atomically and keep Profile/Custom state in sync.

    Profiles are presets only. Standard and Advanced editors both modify the same
    effective YAML policy. Any non-profile edit therefore marks the effective
    policy as Custom while preserving the selected profile as its base.
    """
    base_profile = None
    if source != "profile":
        try:
            from profiles import PROFILES
            before = load_policy(path)
            base_profile = _policy_state(path, before, PROFILES).get("base_profile")
        except Exception:
            base_profile = None

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    try:
        # Apply the complete edit set in memory and validate once.  This avoids
        # re-reading/re-parsing a large policy dozens of times when switching a
        # profile and also prevents a half-applied profile from becoming visible.
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        for pth, value in changes.items():
            _patch_yaml_lines(lines, pth, value)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text("".join(lines), encoding="utf-8")
        load_policy(tmp)
        tmp.replace(path)
        if source != "profile":
            _mark_policy_custom(path, base_profile)
    except Exception:
        shutil.copy2(backup, path)
        raise
    return backup


def cycle_value(setting: Setting, current: Any, reverse: bool = False):
    if setting.kind == "bool":
        return not bool(current)
    opts = setting.options
    if not opts:
        return current
    try:
        idx = opts.index(current)
    except ValueError:
        idx = 0
    return opts[(idx + (-1 if reverse else 1)) % len(opts)]


def fmt_value(v: Any) -> str:
    if v is True:
        return "ON"
    if v is False:
        return "OFF"
    if v is None:
        return "NOT SET"
    if isinstance(v, list):
        return f"[{len(v)} items]"
    if isinstance(v, dict):
        return f"{{{len(v)} items}}"
    return str(v).upper()


def fmt_setting_value(setting: Setting, value: Any) -> str:
    try:
        if value in setting.value_labels:
            return setting.value_labels[value]
    except TypeError:
        pass
    return fmt_value(value)


def setting_inline_help(setting: Setting, value: Any) -> str:
    try:
        return setting.value_help.get(value, setting.help)
    except TypeError:
        return setting.help


def _is_help_key(ch: int) -> bool:
    return ch in {ord("?"), getattr(curses, "KEY_F1", -10001)}


def safe_addstr(win, y: int, x: int, text: str, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    try:
        win.addnstr(y, x, str(text), max(0, w - x - 1), attr)
    except curses.error:
        pass


def init_colors():
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_CYAN)


def color(n: int):
    return curses.color_pair(n) if curses.has_colors() else 0


def draw_header(stdscr, title: str, subtitle: str = "", footer: str = "q: Back/Exit   ↑↓: Navigate   Enter: Select"):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, " " * max(0, w - 1), color(5))
    safe_addstr(stdscr, 0, 2, f"Suricata Policy Engine  |  {title}", color(5) | curses.A_BOLD)
    if subtitle:
        safe_addstr(stdscr, 2, 2, subtitle, curses.A_DIM)
    safe_addstr(stdscr, h - 1, 2, footer, curses.A_DIM)


def pause_screen(stdscr, message="Press any key to continue..."):
    h, _ = stdscr.getmaxyx()
    safe_addstr(stdscr, h - 2, 2, message, color(3))
    stdscr.refresh()
    stdscr.getch()


def text_viewer(stdscr, title: str, lines: list[str] | str, subtitle: str = ""):
    """Scrollable text viewer optimized for SSH/remote terminals.

    Text wrapping is cached by terminal width. Arrow/Page scrolling repaints only
    the body viewport unless the terminal is resized, avoiding an expensive full
    header/screen redraw on every key press.
    """
    if isinstance(lines, str):
        source_lines = lines.splitlines() or [""]
    else:
        source_lines = [str(x) for x in lines]
    top = 0
    cached_width = None
    rendered: list[str] = []
    last_size = None
    needs_full = True

    def render_body(h: int, w: int, page: int) -> None:
        # Clear only the content area. Header/footer remain untouched.
        for row in range(4, max(4, h - 1)):
            safe_addstr(stdscr, row, 2, " " * max(0, w - 4))
        for row, line in enumerate(rendered[top:top + page]):
            safe_addstr(stdscr, 4 + row, 3, line)
        # Status occupies the subtitle row at the right; clear its area first.
        status_x = max(2, w - 28)
        safe_addstr(stdscr, 2, status_x, " " * max(0, w - status_x - 2))
        if len(rendered) > page:
            safe_addstr(stdscr, 2, status_x,
                        f"Lines {top+1}-{min(top+page,len(rendered))}/{len(rendered)}",
                        curses.A_DIM)

    while True:
        h, w = stdscr.getmaxyx()
        width = max(20, w - 6)
        if width != cached_width:
            rendered = []
            for line in source_lines:
                if not line:
                    rendered.append("")
                    continue
                rendered.extend(textwrap.wrap(line, width=width, replace_whitespace=False,
                                              drop_whitespace=False) or [""])
            cached_width = width
            needs_full = True
        page = max(4, h - 6)
        top = max(0, min(top, max(0, len(rendered) - page)))
        size = (h, w)
        if size != last_size:
            last_size = size
            needs_full = True

        if needs_full:
            draw_header(stdscr, title, subtitle,
                        "q: Back   ↑↓: Scroll   PgUp/PgDn: Page   Home/End: Jump")
        render_body(h, w, page)
        stdscr.refresh()
        needs_full = False

        ch = stdscr.getch()
        old_top = top
        if ch in (ord("q"), 27):
            return
        if ch in (curses.KEY_UP, ord("k")):
            top -= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            top += 1
        elif ch == curses.KEY_PPAGE:
            top -= page
        elif ch == curses.KEY_NPAGE:
            top += page
        elif ch == curses.KEY_HOME:
            top = 0
        elif ch == curses.KEY_END:
            top = max(0, len(rendered) - page)
        elif ch == getattr(curses, "KEY_RESIZE", -9999):
            needs_full = True
        top = max(0, min(top, max(0, len(rendered) - page)))
        # Unknown keys do not force any redraw.
        if top == old_top and not needs_full:
            continue

def setting_help_lines(setting: Setting, current: Any) -> list[str]:
    """Human-oriented help for an advanced policy setting."""
    path = ".".join(setting.path)
    low = (setting.label + " " + path).lower()
    if "force-enable" in low or "force_enable" in low:
        risk = "HIGH"
        advice = "Change only for a reviewed exception. This can re-enable a rule the feed intentionally disabled."
    elif any(x in low for x in ("semantic", "regex", "suppression", "baseline", "gpl mapping")):
        risk = "HIGH"
        advice = "Review carefully and run Tune My Rules afterwards. A bad value can hide alerts or classify rules incorrectly."
    elif any(x in low for x in ("dependency", "validation", "mode", "strategy", "threshold")):
        risk = "MEDIUM"
        advice = "Prefer the current default unless you understand the effect. Validate with Tune My Rules after changing it."
    else:
        risk = "LOW / CONTEXT DEPENDENT"
        advice = "Change when it reflects your actual environment or organization policy."

    if setting.kind == "bool":
        how = "Space/Left/Right toggles ON/OFF."
    elif setting.kind in {"tri", "enum"}:
        how = "Space/Left/Right cycles through the allowed values."
    elif setting.kind in {"str_list", "int_list"}:
        how = "Enter opens the list editor; add, edit, or delete individual values."
    else:
        how = "Press Enter to edit the value."

    return [
        setting.label,
        "",
        f"What it does: {setting_inline_help(setting, current) or 'Advanced policy control.'}",
        f"Current value: {fmt_value(current)}",
        f"Policy path: {path}",
        f"Risk: {risk}",
        f"How to edit: {how}",
        f"Recommendation: {advice}",
        "",
        "Rule of thumb: if you are unsure, leave Advanced Settings unchanged and use Standard Settings instead.",
    ]


def input_text(stdscr, prompt: str, initial: str = "") -> Optional[str]:
    h, w = stdscr.getmaxyx()
    y = h - 3
    safe_addstr(stdscr, y, 1, " " * max(0, w - 2))
    safe_addstr(stdscr, y, 2, prompt, color(1) | curses.A_BOLD)
    x = min(w - 2, 2 + len(prompt) + 1)
    curses.echo()
    curses.curs_set(1)
    try:
        # Initial text is shown as a hint; user can press Enter to keep it.
        if initial:
            safe_addstr(stdscr, y - 1, 2, f"Current: {initial}", curses.A_DIM)
        stdscr.move(y, x)
        raw = stdscr.getstr(y, x, max(1, w - x - 2))
        text = raw.decode("utf-8", errors="replace")
    finally:
        curses.noecho()
        curses.curs_set(0)
    if text == "" and initial:
        return initial
    return text


def confirm(stdscr, message: str) -> bool:
    h, w = stdscr.getmaxyx()
    box_w = min(max(len(message) + 8, 50), max(20, w - 4))
    y = max(2, h // 2 - 2)
    x = max(1, (w - box_w) // 2)
    win = curses.newwin(5, box_w, y, x)
    win.box()
    safe_addstr(win, 1, 2, message, curses.A_BOLD)
    safe_addstr(win, 3, 2, "Press y to confirm, any other key to cancel", color(3))
    win.refresh()
    return win.getch() in (ord("y"), ord("Y"))


def advanced_settings_warning(stdscr) -> bool:
    """Clear, modal warning before entering Advanced Settings.

    Enter continues and Esc/q returns. No hidden letter shortcut is required.
    """
    lines = [
        "Advanced Settings can change detection behavior.",
        "",
        "Use this area only when you need category strategies, dependencies,",
        "semantic selectors, SID exceptions, thresholds, validation, or mappings.",
        "",
        "Normal day-to-day changes are safer in Standard Settings.",
    ]
    while True:
        draw_header(stdscr, "Advanced Settings", "Review before continuing",
                    "Enter: Continue   Esc/q: Back")
        for i, line in enumerate(lines):
            attr = color(3) | curses.A_BOLD if i == 0 else 0
            safe_addstr(stdscr, 4 + i, 4, line, attr)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (10, 13):
            return True
        if ch in (27, ord("q")):
            return False


def choose_menu(stdscr, title: str, items: list[tuple[str, str]], subtitle: str = "",
                help_lines: Optional[list[str]] = None,
                show_selected_description: bool = False,
                selected_detail_descriptions: Optional[dict[str, str]] = None) -> Optional[str]:
    """Scrollable menu optimized for low-latency keyboard navigation.

    Arrow-key moves repaint only the old/new rows.  When a bottom explanation
    panel is enabled, only that small panel is repainted as selection changes.
    A full-screen redraw is reserved for viewport shifts and terminal resize.
    """
    selectable = [i for i, (name, _desc) in enumerate(items) if str(name).strip()]
    if not selectable:
        return None
    sel_pos = 0
    top = 0
    needs_full = True
    last_size = None

    def row_for(index: int, current_top: int) -> int:
        return 4 + (index - current_top)

    def draw_item(index: int, current_top: int, selected_index: int) -> None:
        h, w = stdscr.getmaxyx()
        row = row_for(index, current_top)
        if row < 4 or row >= h - 1:
            return
        name, desc = items[index]
        safe_addstr(stdscr, row, 2, " " * max(0, w - 4))
        if not str(name).strip():
            if str(desc).strip():
                safe_addstr(stdscr, row, 3, str(desc), color(1) | curses.A_BOLD)
            return
        attr = curses.A_REVERSE if index == selected_index else 0
        safe_addstr(stdscr, row, 3, f"{name:<28}", attr | curses.A_BOLD)
        safe_addstr(stdscr, row, 33, desc, attr)

    def draw_detail_panel(selected_index: int) -> None:
        if not show_selected_description:
            return
        h, w = stdscr.getmaxyx()
        panel_y = max(5, h - 6)
        # Clear only the explanation area, never the footer on h-1.
        for row in range(panel_y, max(panel_y, h - 1)):
            safe_addstr(stdscr, row, 2, " " * max(0, w - 4))
        selected_name, selected_desc = items[selected_index]
        detail = (selected_detail_descriptions or {}).get(selected_name, selected_desc)
        safe_addstr(stdscr, panel_y, 3, f"About {selected_name}:", color(1) | curses.A_BOLD)
        width = max(24, w - 6)
        wrapped = textwrap.wrap(str(detail), width=width,
                                replace_whitespace=False, drop_whitespace=True) or [""]
        for off, line in enumerate(wrapped[:3], start=1):
            safe_addstr(stdscr, panel_y + off, 3, line, curses.A_DIM)

    while True:
        sel = selectable[sel_pos]
        h, w = stdscr.getmaxyx()
        size = (h, w)
        page = max(4, h - (11 if show_selected_description else 6))
        if sel < top:
            top = sel
            needs_full = True
        if sel >= top + page:
            top = sel - page + 1
            needs_full = True
        if size != last_size:
            needs_full = True
            last_size = size

        if needs_full:
            footer = "q: Back   ↑↓: Navigate   Enter: Select"
            if help_lines:
                footer += "   ?: Help"
            draw_header(stdscr, title, subtitle, footer)
            for idx in range(top, min(len(items), top + page)):
                draw_item(idx, top, sel)
            draw_detail_panel(sel)
            stdscr.refresh()
            needs_full = False

        ch = stdscr.getch()
        if ch in (ord("q"), 27):
            return None
        if ch in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j")):
            old_sel = sel
            old_top = top
            if ch in (curses.KEY_UP, ord("k")):
                sel_pos = (sel_pos - 1) % len(selectable)
            else:
                sel_pos = (sel_pos + 1) % len(selectable)
            new_sel = selectable[sel_pos]
            if new_sel < top:
                top = new_sel
            elif new_sel >= top + page:
                top = new_sel - page + 1
            if top == old_top:
                draw_item(old_sel, top, new_sel)
                draw_item(new_sel, top, new_sel)
                draw_detail_panel(new_sel)
                stdscr.refresh()
            else:
                needs_full = True
        elif _is_help_key(ch) and help_lines:
            text_viewer(stdscr, f"Help / {title}", help_lines, "Help for this screen")
            needs_full = True
        elif ch in (10, 13, ord(" ")):
            return items[selectable[sel_pos]][0]
        elif ch == getattr(curses, "KEY_RESIZE", -9999):
            needs_full = True

def list_editor(stdscr, title: str, values: list[Any], integer: bool = False) -> list[Any]:
    vals = list(values or [])
    sel = 0
    while True:
        draw_header(stdscr, title, "a: add   e/Enter: edit   d: delete   q: done", "q: Done   a: Add   e: Edit   d: Delete")
        h, _ = stdscr.getmaxyx()
        page = max(4, h - 7)
        if vals:
            sel = max(0, min(sel, len(vals) - 1))
        top = max(0, sel - page + 1)
        for row, idx in enumerate(range(top, min(len(vals), top + page))):
            attr = curses.A_REVERSE if idx == sel else 0
            safe_addstr(stdscr, 4 + row, 3, f"{idx+1:>3}. {vals[idx]}", attr)
        if not vals:
            safe_addstr(stdscr, 4, 3, "(empty)", curses.A_DIM)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("q"), 27):
            return vals
        if ch in (curses.KEY_UP, ord("k")) and vals:
            sel = (sel - 1) % len(vals)
        elif ch in (curses.KEY_DOWN, ord("j")) and vals:
            sel = (sel + 1) % len(vals)
        elif ch == ord("a"):
            txt = input_text(stdscr, "New value:")
            if txt is not None and txt != "":
                try:
                    vals.append(int(txt) if integer else txt)
                    sel = len(vals) - 1
                except ValueError:
                    pass
        elif ch in (ord("e"), 10, 13) and vals:
            txt = input_text(stdscr, "New value (Enter keeps current):", str(vals[sel]))
            if txt is not None:
                try:
                    vals[sel] = int(txt) if integer else txt
                except ValueError:
                    pass
        elif ch in (ord("d"), curses.KEY_DC) and vals:
            del vals[sel]
            sel = max(0, sel - 1)


def edit_settings(stdscr, args, title: str, settings: list[Setting], subtitle: str = ""):
    try:
        policy = load_policy(args.policy)
    except Exception as exc:
        draw_header(stdscr, title)
        safe_addstr(stdscr, 4, 2, f"Cannot load policy: {exc}", color(4))
        pause_screen(stdscr)
        return
    selected, top = 0, 0
    dirty: dict[tuple[str, ...], Any] = {}

    while True:
        draw_header(stdscr, title, subtitle or "Space/←/→: toggle   Enter: edit   s: save   ?: help",
                    "q: Back   ↑↓: Navigate   ←→/Space: Change   Enter: Edit   ?: Help   s: Save")
        h, w = stdscr.getmaxyx()
        page = max(5, h - 7)
        if selected < top:
            top = selected
        if selected >= top + page:
            top = selected - page + 1
        for row, idx in enumerate(range(top, min(len(settings), top + page))):
            st = settings[idx]
            val = dirty.get(st.path, get_path(policy, st.path))
            attr = curses.A_REVERSE if idx == selected else 0
            safe_addstr(stdscr, 4 + row, 3, f"{st.label:<42}", attr)
            safe_addstr(stdscr, 4 + row, 47, f"{fmt_setting_value(st, val):<22}", attr | curses.A_BOLD)
        if settings:
            safe_addstr(stdscr, h - 3, 2, setting_inline_help(settings[selected], dirty.get(settings[selected].path, get_path(policy, settings[selected].path))), curses.A_DIM)
        if dirty:
            safe_addstr(stdscr, 2, max(2, w - 30), f"Unsaved changes: {len(dirty)}", color(3) | curses.A_BOLD)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("q"), 27):
            if not dirty or confirm(stdscr, "Discard unsaved policy changes?"):
                return
        elif ch in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(settings)
        elif ch in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(settings)
        elif ch in (curses.KEY_LEFT, ord("h"), curses.KEY_RIGHT, ord("l"), ord(" ")):
            st = settings[selected]
            if st.kind in {"bool", "tri", "enum"}:
                cur = dirty.get(st.path, get_path(policy, st.path))
                dirty[st.path] = cycle_value(st, cur, reverse=ch in (curses.KEY_LEFT, ord("h")))
        elif ch in (10, 13):
            st = settings[selected]
            cur = dirty.get(st.path, get_path(policy, st.path))
            if st.kind in {"bool", "tri", "enum"}:
                dirty[st.path] = cycle_value(st, cur)
            elif st.kind == "int":
                txt = input_text(stdscr, f"{st.label}:", str(cur if cur is not None else ""))
                try:
                    if txt is not None:
                        dirty[st.path] = int(txt)
                except ValueError:
                    pass
            elif st.kind == "text":
                txt = input_text(stdscr, f"{st.label}:", str(cur or ""))
                if txt is not None:
                    dirty[st.path] = txt
            elif st.kind in {"str_list", "int_list"}:
                dirty[st.path] = list_editor(stdscr, st.label, list(cur or []), integer=st.kind == "int_list")
        elif ch == ord("r"):
            policy = load_policy(args.policy)
            dirty.clear()
        elif _is_help_key(ch) and settings:
            st = settings[selected]
            cur = dirty.get(st.path, get_path(policy, st.path))
            text_viewer(stdscr, f"Help / {st.label}", setting_help_lines(st, cur),
                        "Context help for this advanced policy control")
        elif ch == ord("s") and dirty:
            try:
                backup = apply_policy_changes(args.policy, dirty)
                policy = load_policy(args.policy)
                dirty.clear()
                safe_addstr(stdscr, h - 2, 2, f"Saved. Active Policy: {_active_policy_label(args.policy)}", color(2))
            except Exception as exc:
                safe_addstr(stdscr, h - 2, 2, f"Save failed: {exc}", color(4))
            stdscr.refresh()
            curses.napms(1400)


def category_policy_editor(stdscr, args):
    """Edit category mode/strategy without allowing malformed state to kill the TUI."""
    while True:
        try:
            policy = load_policy(args.policy)
        except Exception as exc:
            text_viewer(stdscr, "Category Policy / Policy Error", [
                "Category Policy could not load the current YAML.",
                "",
                f"{type(exc).__name__}: {exc}",
                "",
                "The editor returned safely without changing the policy.",
            ])
            return
        cats = policy.get("categories", {}) or {}
        if not isinstance(cats, dict) or not cats:
            text_viewer(stdscr, "Category Policy", ["No category mappings are available in the current policy."])
            return
        items = []
        for name, cfg in cats.items():
            if not isinstance(cfg, dict):
                cfg = {}
            mode = str(cfg.get("mode") or "?")
            if mode == "conditional":
                raw_strategy = str(cfg.get("strategy") or "selective")
                short_strategy = {
                    "selective": "Selective / feed first",
                    "enabled_by_default": "Keep feed-enabled",
                    "enabled_by_default_with_alert_tuning": "Keep + noise control",
                    "disabled_by_default": "Off by default",
                    "organization_policy": "Organization policy",
                    "organization_policy_selective": "Org policy (reviewed matches)",
                    "default_disabled_with_allowlist": "Off except reviewed exceptions",
                    "message_filter": "Feed + message filters",
                }.get(raw_strategy, raw_strategy)
                desc = f"Conditional -> {short_strategy}"
            else:
                desc = {
                    "preserve_feed": "Preserve feed",
                    "disable": "Disable category",
                    "asset_based": "Use asset inventory",
                }.get(mode, str(mode).replace("_", " ").title())
            items.append((name, desc))
        name = choose_menu(
            stdscr,
            "Policy Editor / Category Policy",
            items,
            "Mode = first decision. Strategy = second decision, used only when Mode is CONDITIONAL.",
            [
                "CATEGORY POLICY: MODE VS STRATEGY",
                "",
                "Mode is the first-stage decision for a category.",
                "Strategy exists only when Mode=CONDITIONAL and decides how that conditional category is resolved.",
                "",
                "DECISION FLOW",
                "",
                "PRESERVE_FEED -> stop: follow the feed's enabled/disabled state.",
                "DISABLE       -> stop: turn the category off; required dependencies can still be restored.",
                "ASSET_BASED   -> stop: use confirmed asset/technology context.",
                "CONDITIONAL   -> continue to Strategy for the second-stage decision.",
                "",
                "CONDITIONAL STRATEGIES",
                "",
                "Selective / feed first      - Preserve feed state unless a reviewed exception changes it.",
                "Keep feed-enabled             - Keep rules the upstream feed ships enabled.",
                "Keep + noise control           - Keep feed-enabled rules and rate-limit repetitive alerts.",
                "Off by default                 - Keep off unless another explicit policy decision enables it.",
                "Organization policy            - Resolve the category from one usage/detection decision.",
                "Org policy (reviewed matches)  - Apply org decisions only to reviewed families; preserve unmatched rules.",
                "Off except reviewed exceptions - Only Semantic Selectors / SID exceptions and dependencies can keep it.",
                "Feed + message filters         - Follow the feed except for configured message filters.",
                "",
                "Example: ET_TOR uses Mode=CONDITIONAL. Its strategy then decides whether organization policy enables detection.",
            ],
        )
        if not name:
            return
        cfg = cats.get(name, {}) or {}
        if not isinstance(cfg, dict):
            cfg = {}
        mode = str(cfg.get("mode") or "preserve_feed")
        strategy = str(cfg.get("strategy") or "selective") if mode == "conditional" else None
        # Keep the first three controls consistent for every category.  Strategy
        # and fallback are stored even when inactive so the screen never looks
        # incomplete; their help text makes clear when they actually take effect.
        mode_labels = {
            "preserve_feed": "Preserve feed",
            "disable": "Disable category",
            "asset_based": "Use asset inventory",
            "conditional": "Use conditional policy",
        }
        mode_help = {
            "preserve_feed": "Keep each rule exactly as the upstream feed ships it (enabled stays enabled; disabled stays disabled).",
            "disable": "Turn this category off by policy. Required flowbit/xbit dependencies may still be restored automatically.",
            "asset_based": "Decide from the Assets inventory. A relevant enabled asset keeps the feed rule; an absent/disabled asset does not.",
            "conditional": "Use the second-stage Conditional Strategy shown below.",
        }
        strategy_labels = {
            "selective": "Selective / feed first",
            "enabled_by_default": "Keep feed-enabled",
            "enabled_by_default_with_alert_tuning": "Keep + noise control",
            "disabled_by_default": "Off by default",
            "organization_policy": "Organization policy",
            "organization_policy_selective": "Org policy (reviewed matches)",
            "default_disabled_with_allowlist": "Off except reviewed exceptions",
            "message_filter": "Feed + message filters",
        }
        strategy_help = {
            "selective": "Preserve the feed unless a reviewed semantic/SID exception changes the decision.",
            "enabled_by_default": "Keep rules that the feed ships enabled; do not resurrect upstream-disabled rules.",
            "enabled_by_default_with_alert_tuning": "Keep feed-enabled rules and apply configured alert-rate controls to reduce repeats.",
            "disabled_by_default": "Keep this conditional category off unless another explicit policy decision enables it.",
            "organization_policy": "Use the matching Organization Policy activity (allowed/prohibited + detect ON/OFF).",
            "organization_policy_selective": "Only reviewed semantic families use Organization Policy; unmatched rules keep their upstream feed state.",
            "default_disabled_with_allowlist": "Off by default. Only reviewed Semantic Selectors / SID exceptions (plus required dependencies) can keep a rule. Those exceptions live under Rule Overrides and Semantic Selectors.",
            "message_filter": "Keep the upstream feed state except for the configured message text/regex filters in this category.",
        }
        settings = [
            Setting("Mode", ("categories", name, "mode"), "enum",
                    ("preserve_feed", "disable", "asset_based", "conditional"),
                    "First-stage category action.", value_labels=mode_labels, value_help=mode_help),
            Setting("Conditional strategy", ("categories", name, "strategy"), "enum",
                    ("selective", "enabled_by_default", "enabled_by_default_with_alert_tuning", "disabled_by_default", "organization_policy", "organization_policy_selective", "default_disabled_with_allowlist", "message_filter"),
                    "Used only when Mode=CONDITIONAL.", value_labels=strategy_labels, value_help=strategy_help),
            Setting("Fallback enabled", ("categories", name, "default_enabled"), "bool",
                    help="Fallback only for strategies that need a default ON/OFF choice. It is ignored when the selected strategy does not use it."),
        ]

        if strategy == "message_filter" or "message_filter" in cfg:
            settings.extend([
                Setting("Message filter: disable contains", ("categories", name, "message_filter", "disable_contains"), "str_list", help="Used only by the MESSAGE_FILTER strategy: literal message terms that disable matching rules."),
                Setting("Message filter: disable regex", ("categories", name, "message_filter", "disable_regex"), "str_list", help="Used only by the MESSAGE_FILTER strategy: regex patterns that disable matching rules."),
            ])

        subtitle = {
            "preserve_feed": "Feed state is authoritative. No additional category decision is required.",
            "disable": "This category is OFF by policy. Required flowbit/xbit setters may still be restored globally when needed.",
            "asset_based": "This category follows confirmed asset context; configure assets in the Assets section.",
            "conditional": f"This category is resolved by the {str(strategy or 'selective').upper()} strategy.",
        }.get(mode, "Review the category mode and only the controls relevant to it.")
        edit_settings(stdscr, args, f"Category / {name}", settings, subtitle)


def defaults_editor(stdscr, args):
    settings = [
        Setting("Preserve dependencies", ("defaults", "preserve_dependencies"), help="Restore required state-setter rules instead of breaking enabled detections."),
        Setting("Dependency restore enabled", ("defaults", "dependency_restore", "enabled"), help="Master switch for dependency restoration."),
        Setting("Only restore when required", ("defaults", "dependency_restore", "only_if_required_by_enabled_rule"), help="Avoid orphan setter rules."),
        Setting("Restore after final policy", ("defaults", "dependency_restore", "run_after_final_policy_resolution"), help="Resolve dependencies after all policy decisions."),
        Setting("Dependency types", ("defaults", "dependency_types"), "str_list", help="Normally flowbits and xbits."),
        Setting("Disable unknown categories", ("defaults", "disable_unknown_categories"), help="OFF is safer: new feed categories preserve vendor state."),
    ]
    edit_settings(stdscr, args, "Policy Editor / Defaults & Dependencies", settings)


ASSET_LABELS = {
    "web_server": "Web server",
    "scada": "SCADA / ICS",
    "activex": "ActiveX",
    "voip": "VoIP / SIP",
    "nginx": "Nginx",
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "apache_tomcat": "Apache Tomcat",
    "apache_struts": "Apache Struts",
    "jboss": "JBoss",
    "exchange": "Microsoft Exchange",
    "sharepoint": "Microsoft SharePoint",
    "citrix": "Citrix",
    "manageengine": "ManageEngine",
    "servicenow": "ServiceNow",
    "oracle_ebs": "Oracle E-Business Suite",
    "oracle_weblogic": "Oracle WebLogic",
    "sap": "SAP",
    "commvault": "Commvault",
    "kaseya": "Kaseya",
    "confluence": "Atlassian Confluence",
    "jira": "Atlassian JIRA",
    "jenkins": "Jenkins",
    "teamcity": "JetBrains TeamCity",
    "gitlab": "GitLab",
    "grafana": "Grafana",
    "zabbix": "Zabbix",
    "nagios": "Nagios",
    "cacti": "Cacti",
    "glpi": "GLPI",
    "kubernetes": "Kubernetes",
    "progress_whatsup_gold": "Progress WhatsUp Gold",
    "fortinet": "Fortinet / FortiGate",
    "sonicwall": "SonicWall",
    "f5": "F5 BIG-IP",
    "cisco": "Cisco",
    "ivanti": "Ivanti / Pulse Secure",
    "palo_alto": "Palo Alto Networks",
    "zyxel": "Zyxel",
    "dlink": "D-Link",
    "tplink": "TP-Link",
    "netgear": "Netgear",
    "linksys": "Linksys",
    "tenda": "Tenda",
    "totolink": "Totolink",
    "wavlink": "Wavlink",
    "ipfire": "IPFire",
    "abb_cylon": "ABB Cylon",
    "microhard": "Microhard Systems",
    "utt": "UTT",
    "moveit": "Progress MOVEit",
    "goanywhere": "Fortra GoAnywhere",
    "crushftp": "CrushFTP",
    "roundcube": "Roundcube",
    "mssql": "Microsoft SQL Server",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "oracle_database": "Oracle Database",
    "sap_maxdb": "SAP MaxDB",
}

ASSET_GROUPS = [
    ("Core technologies", ["web_server", "scada", "activex", "voip"]),
    ("Web & CMS", ["nginx", "wordpress", "joomla", "drupal", "apache_tomcat", "apache_struts", "jboss"]),
    ("Enterprise applications", ["exchange", "sharepoint", "citrix", "manageengine", "servicenow", "oracle_ebs", "oracle_weblogic", "sap", "commvault", "kaseya"]),
    ("DevOps & monitoring", ["confluence", "jira", "jenkins", "teamcity", "gitlab", "grafana", "zabbix", "nagios", "cacti", "glpi", "kubernetes", "progress_whatsup_gold"]),
    ("Network & security", ["fortinet", "sonicwall", "f5", "cisco", "ivanti", "palo_alto", "zyxel", "dlink", "tplink", "netgear", "linksys", "tenda", "totolink", "wavlink", "ipfire", "abb_cylon", "microhard", "utt"]),
    ("File transfer & collaboration", ["moveit", "goanywhere", "crushftp", "roundcube"]),
    ("Databases", ["mssql", "mysql", "mariadb", "postgresql", "oracle_database", "sap_maxdb"]),
]

CORE_ASSETS = {"web_server", "scada", "activex", "voip"}
DATABASE_ASSETS = {"mssql", "mysql", "mariadb", "postgresql", "oracle_database", "sap_maxdb"}

_FEED_PRODUCT_CACHE: dict[tuple[str, int, int], list[tuple[str, int]]] = {}


def _feed_product_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")
    if not slug:
        slug = "product"
    # Include a short hash so two metadata values that normalize to the same slug
    # remain distinct and stable in the YAML mapping.
    digest = hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:8]
    return f"{slug[:72]}_{digest}"


def _discover_feed_products(rules_path: Path) -> list[tuple[str, int]]:
    """Return every affected_product value found in the operator's current feed."""
    stat = rules_path.stat()
    cache_key = (str(rules_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size))
    cached = _FEED_PRODUCT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    import tune_rules as tuner
    counts: Counter[str] = Counter()
    for raw, _enabled in tuner.core.iter_rule_records(rules_path):
        metadata = tuner.core.parse_metadata(raw)
        for value in metadata.get("affected_product", []) or []:
            value = str(value).strip()
            if value:
                counts[value] += 1
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    _FEED_PRODUCT_CACHE.clear()
    _FEED_PRODUCT_CACHE[cache_key] = rows
    return rows


def _curated_affected_product_map(policy: dict) -> dict[str, tuple[str, str, str]]:
    out: dict[str, tuple[str, str, str]] = {}
    apps = get_path(policy, ("assets", "web_specific_apps"), {}) or {}
    databases = get_path(policy, ("assets", "database_products"), {}) or {}
    for key, cfg in apps.items():
        if not isinstance(cfg, dict):
            continue
        for value in ((cfg.get("metadata", {}) or {}).get("affected_product", []) or []):
            if not str(value).startswith("re:"):
                out[re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()] = (key, ASSET_LABELS.get(key, key), "web_app")
    for key, cfg in databases.items():
        if not isinstance(cfg, dict):
            continue
        for value in ((cfg.get("metadata", {}) or {}).get("affected_product", []) or []):
            if not str(value).startswith("re:"):
                out[re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()] = (key, ASSET_LABELS.get(key, key), "database")
    return out


def _feed_products_editor(stdscr, args):
    """Show all affected_product metadata values from the current local ruleset."""
    if not args.rules.exists():
        text_viewer(stdscr, "Assets / Feed-discovered products", [f"Rules file not found: {args.rules}"])
        return
    draw_header(stdscr, "Assets / Feed-discovered products", "Scanning affected_product metadata from the current ruleset...")
    stdscr.refresh()
    try:
        census = _discover_feed_products(args.rules)
    except Exception as exc:
        text_viewer(stdscr, "Assets / Feed-discovered products", [f"Could not scan rules: {exc}"])
        return
    while True:
        policy = load_policy(args.policy)
        curated = _curated_affected_product_map(policy)
        overrides = get_path(policy, ("assets", "feed_products"), {}) or {}
        items: list[tuple[str, str]] = []
        detail: dict[str, str] = {}
        lookup: dict[str, tuple[str, int, Optional[tuple[str, str, str]]]] = {}
        seen_labels: Counter[str] = Counter()
        for raw_value, count in census:
            norm = re.sub(r"[^a-z0-9]+", " ", raw_value.lower()).strip()
            covered = curated.get(norm)
            slug = _feed_product_slug(raw_value)
            cfg = overrides.get(slug, {}) if isinstance(overrides, dict) else {}
            enabled = bool(cfg.get("enabled", False)) if isinstance(cfg, dict) else False
            base_label = raw_value
            seen_labels[base_label] += 1
            label = base_label if seen_labels[base_label] == 1 else f"{base_label} [{seen_labels[base_label]}]"
            if covered:
                status = f"Covered by {covered[1]} | {count} rule(s)"
                about = f"affected_product={raw_value} appears in {count} rule(s). It is already covered by the reviewed asset matcher: {covered[1]}. Enter opens that asset."
            else:
                status = f"{'ON' if enabled else 'OFF'} | {count} rule(s)"
                about = f"affected_product={raw_value} appears in {count} rule(s). No curated matcher covers it yet. ON adds an exact metadata-based asset fallback for asset-based WEB_SPECIFIC_APPS/SQL decisions."
            items.append((label, status))
            detail[label] = about
            lookup[label] = (raw_value, count, covered)
        if not items:
            text_viewer(stdscr, "Assets / Feed-discovered products", ["No affected_product metadata values were found in the current ruleset."])
            return
        choice = choose_menu(
            stdscr, "Assets / Feed-discovered products", items,
            f"{len(census)} unique affected_product values found in {args.rules.name}. This list comes from your current feed, not a static catalog.",
            [
                "FEED-DISCOVERED PRODUCTS",
                "",
                "This screen reads affected_product metadata directly from the current suricata.rules file.",
                "Covered products use the reviewed matcher catalog. Uncovered products can be enabled as exact metadata fallbacks.",
                "An exact feed-product fallback is used only when no curated matcher already identifies the rule.",
            ],
            show_selected_description=True, selected_detail_descriptions=detail,
        )
        if not choice:
            return
        raw_value, _count, covered = lookup[choice]
        if covered:
            key, label, kind = covered
            _asset_detail_editor(stdscr, args, key, label, kind)
            continue
        slug = _feed_product_slug(raw_value)
        current = get_path(policy, ("assets", "feed_products", slug, "enabled"), False)
        new_value = not bool(current)
        if confirm(stdscr, f"Set feed product '{raw_value}' to {'ON' if new_value else 'OFF'}?"):
            try:
                apply_policy_changes(args.policy, {
                    ("assets", "feed_products", slug, "enabled"): new_value,
                    ("assets", "feed_products", slug, "metadata_values"): [raw_value],
                })
            except Exception as exc:
                text_viewer(stdscr, "Asset update failed", [str(exc)])

def _asset_enabled(policy: dict, key: str) -> bool:
    if key in CORE_ASSETS:
        return bool(get_path(policy, ("assets", key, "enabled"), False))
    if key in DATABASE_ASSETS:
        return bool(get_path(policy, ("assets", "database_products", key, "enabled"), False))
    return bool(get_path(policy, ("assets", "web_specific_apps", key, "enabled"), False))

def _asset_group_summary(policy: dict, keys: list[str]) -> str:
    enabled = sum(1 for key in keys if _asset_enabled(policy, key))
    return f"{enabled}/{len(keys)} ON"

def _asset_overview_rows(policy: dict, keys: list[str] | None = None) -> list[tuple[str, str, str, str]]:
    if keys is None:
        keys = [key for _group, group_keys in ASSET_GROUPS for key in group_keys]
    rows = []
    apps = get_path(policy, ("assets", "web_specific_apps"), {}) or {}
    databases = get_path(policy, ("assets", "database_products"), {}) or {}
    for key in keys:
        if key in CORE_ASSETS:
            state = "ON" if _asset_enabled(policy, key) else "OFF"
            rows.append((key, ASSET_LABELS.get(key, key), state, "simple"))
            continue
        if key in DATABASE_ASSETS:
            if key not in databases:
                continue
            state = "ON" if _asset_enabled(policy, key) else "OFF"
            rows.append((key, ASSET_LABELS.get(key, key.replace("_", " ").title()), state, "database"))
            continue
        if key not in apps:
            continue
        state = "ON" if _asset_enabled(policy, key) else "OFF"
        rows.append((key, ASSET_LABELS.get(key, key.replace("_", " ").title()), state, "web_app"))
    return rows

def _asset_group_editor(stdscr, args, group_name: str, keys: list[str]):
    while True:
        policy = load_policy(args.policy)
        rows = _asset_overview_rows(policy, keys)
        lookup = {label: (key, label, kind) for key, label, _state, kind in rows}
        items = [(label, state) for _key, label, state, _kind in rows]
        choice = choose_menu(
            stdscr,
            f"Policy Editor / Assets / {group_name}",
            items,
            "ON/OFF is the normal control. Enter opens matcher details only when needed.",
            [
                "ASSET INVENTORY",
                "",
                "ON  - This product/technology exists in the monitored environment.",
                "OFF - Asset-specific ET_WEB_SPECIFIC_APPS signatures are not selected for it.",
                "",
                "Matching uses structured metadata first, then anchored aliases/regex fallback.",
            ],
        )
        if not choice:
            return
        key, label, kind = lookup[choice]
        _asset_detail_editor(stdscr, args, key, label, kind)

def _asset_detail_editor(stdscr, args, asset_key: str, label: str, asset_type: str):
    if asset_type == "simple":
        settings = [
            Setting("Present in monitored environment", ("assets", asset_key, "enabled"),
                    help=f"ON means {label} exists in the environment monitored by this Suricata sensor."),
        ]
        edit_settings(stdscr, args, f"Asset / {label}", settings,
                      "This switch controls asset-aware policy decisions for this technology")
        return

    base = ("assets", "database_products", asset_key) if asset_type == "database" else ("assets", "web_specific_apps", asset_key)
    settings = [
        Setting("Present in monitored environment", base + ("enabled",),
                help=f"ON means {label} is actually deployed in the monitored environment."),
        Setting("Match confidence threshold", base + ("match_threshold",), "int",
                help="Minimum confidence score required before a rule is automatically treated as belonging to this asset."),
        Setting("Review confidence threshold", base + ("review_threshold",), "int",
                help="Lower confidence boundary for ambiguous matches that should be surfaced for admin review."),
        Setting("Known product aliases", base + ("aliases",), "str_list",
                help="Exact product names/aliases recognized by the matcher."),
        Setting("Metadata affected_product values", base + ("metadata", "affected_product"), "str_list",
                help="Structured affected_product metadata values accepted as strong evidence for this asset."),
        Setting("Message regex fallback", base + ("msg_regex",), "str_list",
                help="Controlled fallback regex patterns used only when structured metadata/aliases are insufficient."),
    ]
    edit_settings(stdscr, args, f"Asset / {label}", settings,
                  "Normally only change Present. Matching internals are advanced controls.")


def assets_editor(stdscr, args, title: str = "Policy Editor / Assets"):
    """Grouped asset inventory derived from rule coverage; matcher internals stay one Enter deeper."""
    while True:
        policy = load_policy(args.policy)
        lookup = {name: keys for name, keys in ASSET_GROUPS}
        # Do not parse the full ~68k-rule feed merely to draw this menu.  The
        # comprehensive affected_product census is intentionally on-demand.
        items = [("Current feed products", "scan all affected_product values on Enter" if args.rules.exists() else "rules file missing")]
        items.extend((name, _asset_group_summary(policy, keys)) for name, keys in ASSET_GROUPS)
        choice = choose_menu(
            stdscr,
            title,
            items,
            "Assets are grouped so the complete rule-aware inventory stays readable.",
            [
                "ASSET POLICY",
                "",
                "The catalog is based on product families actually represented by the audited ruleset.",
                "Choose a group, then mark only technologies that really exist in your monitored environment.",
                "",
                "ET_WEB_SPECIFIC_APPS remains conservative: unknown or unmatched products stay disabled/reviewable.",
                "Database assets are also tracked. ET_SQL stays PRESERVE_FEED by default; if you explicitly set ET_SQL to ASSET_BASED, these database selections drive that decision.",
            ],
        )
        if not choice:
            return
        if choice == "Current feed products":
            _feed_products_editor(stdscr, args)
        else:
            _asset_group_editor(stdscr, args, choice, lookup[choice])


def _organization_policy_summary(prohibited: Any, detection_enabled: Any) -> str:
    """Human-readable summary without exposing raw null/NOT SET values."""
    detect = bool(detection_enabled)
    if prohibited is True:
        return "Prohibited + Detect" if detect else "Prohibited + Detection OFF"
    if prohibited is False:
        return "Allowed + Detect" if detect else "Allowed + No detection"
    return "No usage decision + Detect" if detect else "No usage decision + No detection"


def _remote_access_summary(cfg: dict) -> str:
    prohibited = str((cfg or {}).get("default_policy", "prohibited")).lower() == "prohibited"
    detect = bool((cfg or {}).get("detection_enabled", False))
    if prohibited:
        return "Prohibited by default + Detect" if detect else "Prohibited by default + Detection OFF"
    return "Allowed by default + Detect" if detect else "Allowed by default + No detection"


def _organization_detail_editor(stdscr, args, key: str, label: str):
    if key != "remote_access":
        settings = [
            Setting("Usage prohibited", ("organization_policy", key, "prohibited"), "tri", (None, False, True),
                    "YES = prohibited by organization policy; NO = explicitly allowed; unset = no organization decision has been recorded."),
            Setting("Detection enabled", ("organization_policy", key, "detection_enabled"),
                    help="ON tells the tuner to retain detections for this activity when the category strategy supports organization policy."),
        ]
        edit_settings(stdscr, args, f"Organization Policy / {label}", settings,
                      "Usage policy and IDS detection are separate decisions")
        return

    policy = load_policy(args.policy)
    ra = get_path(policy, ("organization_policy", "remote_access"), {}) or {}
    settings = [
        Setting("Default usage policy", ("organization_policy", "remote_access", "default_policy"),
                "enum", ("prohibited", "allowed"),
                "Default organization policy for remote-access software."),
        Setting("Detection enabled", ("organization_policy", "remote_access", "detection_enabled"),
                help="ON retains remote-access detections according to the organization-policy strategy."),
    ]
    for app in sorted((ra.get("applications", {}) or {})):
        pretty = app.replace("_", " ").title()
        settings.append(
            Setting(pretty, ("organization_policy", "remote_access", "applications", app),
                    "enum", ("prohibited", "allowed"),
                    f"Organization policy for {pretty}. This does not independently toggle the whole detection category."),
        )
    edit_settings(stdscr, args, "Organization Policy / Remote Access", settings,
                  "Default policy first; per-application exceptions are optional")


def organization_editor(stdscr, args, title: str = "Policy Editor / Organization Policy"):
    """Compact organization-policy overview with one human decision per row."""
    labels = {
        "tor": "TOR",
        "file_sharing": "File sharing",
        "p2p": "P2P",
        "chat": "Chat",
        "dynamic_dns": "Dynamic DNS",
        "games": "Games",
        "inappropriate_content": "Inappropriate content",
        "anonymizers": "Anonymizers / privacy networks",
        "cloud_storage": "Cloud storage / sharing",
        "cleartext_credentials": "Cleartext credentials",
        "outbound_database": "Outbound database access",
    }
    while True:
        policy = load_policy(args.policy)
        org = policy.get("organization_policy", {}) or {}
        items: list[tuple[str, str]] = []
        lookup: dict[str, tuple[str, str]] = {}
        for key, label in labels.items():
            cfg = org.get(key)
            if not isinstance(cfg, dict):
                continue
            items.append((label, _organization_policy_summary(cfg.get("prohibited"), cfg.get("detection_enabled"))))
            lookup[label] = (key, label)
        ra = org.get("remote_access", {}) or {}
        items.append(("Remote access", _remote_access_summary(ra)))
        lookup["Remote access"] = ("remote_access", "Remote Access")

        org_details = {
            "TOR": "Controls whether TOR usage is allowed and whether TOR activity should still alert. Typical SOC posture: Prohibited + Detect.",
            "File sharing": "Controls policy visibility for file-sharing services. Detection can stay ON even when the activity is allowed.",
            "P2P": "Controls peer-to-peer usage policy separately from detection. Use Detect ON when the SOC still wants visibility.",
            "Chat": "Controls chat/messaging usage policy. This is a usage decision, not a blanket security-rule switch.",
            "Dynamic DNS": "Controls Dynamic DNS usage/visibility. Detect ON is useful when DDNS use is restricted or needs review.",
            "Games": "Controls gaming-related policy detections. Usually a low-security-priority usage-policy choice.",
            "Inappropriate content": "Controls content-policy detections. This is organizational policy, not malware/exploit coverage.",
            "Anonymizers / privacy networks": "Controls reviewed anonymizer/privacy-network rules inside the mixed ET POLICY category.",
            "Cloud storage / sharing": "Controls reviewed cloud-storage/sharing policy rules; unmatched ET POLICY rules are not affected.",
            "Cleartext credentials": "Controls reviewed detections for credentials sent in clear text. Detection is normally valuable even if usage policy is unset.",
            "Outbound database access": "Controls reviewed policy detections for unexpected outbound database connections from monitored hosts.",
            "Remote access": "Controls RMM/remote-access tools such as AnyDesk, TeamViewer and ScreenConnect. Per-application exceptions are available inside.",
        }
        choice = choose_menu(
            stdscr,
            title,
            items,
            "Enter opens usage/detection details. The panel at the bottom explains the selected activity.",
            [
                "ORGANIZATION POLICY",
                "",
                "Usage policy and detection are separate: an activity can be allowed but still monitored.",
                "Prohibited + Detect = forbidden to use, but alert when seen.",
                "Allowed + Detect = allowed, but keep SOC visibility.",
                "Allowed + No detection = allowed and this policy does not request alerts.",
                "No usage decision = no allow/prohibit choice has been recorded yet.",
                "",
                "Only reviewed usage-policy families are controlled here. Security detections outside those families are not silently disabled.",
            ],
            show_selected_description=True,
            selected_detail_descriptions=org_details,
        )
        if not choice:
            return
        key, label = lookup[choice]
        _organization_detail_editor(stdscr, args, key, label)

def rule_override_editor(stdscr, args):
    while True:
        policy = load_policy(args.policy)
        ovs = policy.get("rule_overrides", {}) or {}
        items = [(name, f"tracked={len(cfg.get('tracked_keep_sids',[]) or [])}  semantic={len(cfg.get('semantic_keep',[]) or [])}") for name, cfg in ovs.items()]
        name = choose_menu(stdscr, "Policy Editor / Rule Overrides", items, "SID lists are guardrails; semantic selectors are the resilient primary layer")
        if not name:
            return
        cfg = ovs[name]
        settings = [
            Setting("Default action", ("rule_overrides", name, "default_action"), "enum", ("disable", "preserve_feed"), "Documentation/readability field for this override block. Current runtime category behavior comes from categories.<name>.mode/strategy, not from this field."),
            Setting("Tracked keep SIDs", ("rule_overrides", name, "tracked_keep_sids"), "int_list", help="Known high-value SIDs tracked for feed drift."),
            Setting("Force-enable SIDs", ("rule_overrides", name, "force_enable_sids"), "int_list", help="Explicit exception that may override a feed-disabled SID; use sparingly."),
            Setting("On tracked SID change", ("rule_overrides", name, "tracked_sid_policy", "on_change"), "enum", ("keep_if_feed_enabled_and_warn", "warn_only"), "Policy-intent annotation for tracked SID drift. Current v9 runtime always reports drift and preserves a feed-enabled tracked SID; review feed-audit drift before accepting a new baseline."),
            Setting("On tracked SID missing", ("rule_overrides", name, "tracked_sid_policy", "on_missing"), "enum", ("semantic_fallback_and_warn", "warn_only"), "Policy-intent annotation for a missing tracked SID. Current v9 runtime reports the missing SID while semantic selectors independently search for valuable replacement detections."),
            Setting("Baseline file", ("rule_overrides", name, "tracked_sid_policy", "baseline_file"), "text", help="Tracked SID fingerprint baseline path."),
        ]
        semantic = cfg.get("semantic_keep", []) or []
        for idx, selector in enumerate(semantic):
            # Replace each msg_regex list through a path to a generated helper block is not safe with list-index paths.
            # Expose the full semantic_keep collection as an editable structured list via dedicated editor below.
            pass
        edit_settings(stdscr, args, f"Rule Overrides / {name}", settings,
                      "Tracked/force SID controls are editable here; press q then use Semantic Selectors from the section menu")


def semantic_selector_editor(stdscr, args):
    while True:
        policy = load_policy(args.policy)
        ovs = policy.get("rule_overrides", {}) or {}
        items = [(name, f"{len(cfg.get('semantic_keep',[]) or [])} selector(s)") for name, cfg in ovs.items()]
        category = choose_menu(stdscr, "Policy Editor / Semantic Selectors", items)
        if not category:
            return
        selectors = list((ovs.get(category, {}) or {}).get("semantic_keep", []) or [])
        sel = 0
        dirty = False
        while True:
            draw_header(stdscr, f"Semantic Selectors / {category}", "a: add   n: edit name   r: regex list   d: delete   s: save",
                        "q: Back   ↑↓: Navigate   a: Add   n: Name   r: Regex   d: Delete   ?: Help   s: Save")
            h, _ = stdscr.getmaxyx()
            page = max(4, h - 7)
            if selectors:
                sel = max(0, min(sel, len(selectors)-1))
            top = max(0, sel-page+1)
            for row, idx in enumerate(range(top, min(len(selectors), top+page))):
                item = selectors[idx]
                name = item.get("name", f"selector-{idx+1}")
                regs = item.get("msg_regex", []) or []
                attr = curses.A_REVERSE if idx == sel else 0
                safe_addstr(stdscr, 4+row, 3, f"{name:<48} regex={len(regs)}", attr)
            if not selectors:
                safe_addstr(stdscr, 4, 3, "(no semantic selectors)", curses.A_DIM)
            if dirty:
                safe_addstr(stdscr, 2, 55, "UNSAVED", color(3) | curses.A_BOLD)
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (ord("q"), 27):
                if not dirty or confirm(stdscr, "Discard unsaved semantic changes?"):
                    break
            elif ch in (curses.KEY_UP, ord("k")) and selectors:
                sel = (sel-1) % len(selectors)
            elif ch in (curses.KEY_DOWN, ord("j")) and selectors:
                sel = (sel+1) % len(selectors)
            elif ch == ord("a"):
                name = input_text(stdscr, "Selector name:")
                if name:
                    selectors.append({"name": name, "msg_regex": []}); sel=len(selectors)-1; dirty=True
            elif ch == ord("n") and selectors:
                name = input_text(stdscr, "Selector name:", str(selectors[sel].get("name", "")))
                if name is not None:
                    selectors[sel]["name"] = name; dirty=True
            elif ch == ord("r") and selectors:
                selectors[sel]["msg_regex"] = list_editor(stdscr, "Semantic msg_regex", selectors[sel].get("msg_regex", []) or [])
                dirty=True
            elif ch == ord("d") and selectors and confirm(stdscr, "Delete this semantic selector?"):
                del selectors[sel]; sel=max(0,sel-1); dirty=True
            elif _is_help_key(ch):
                text_viewer(stdscr,"Semantic Selectors / Help",[
                    "Semantic selectors keep valuable detections by meaning-oriented rule fields instead of depending only on fixed SID numbers.",
                    "",
                    "msg_regex is evaluated against the rule's msg field. Example: a selector for lateral movement may match a controlled phrase such as 'lateral movement' or a specific PowerShell-over-SMB pattern.",
                    "",
                    "Risk: HIGH. An overly broad regex can enable many unrelated rules; an overly narrow regex can miss a replacement rule after a feed update.",
                    "",
                    "Recommendation: prefer precise, reviewable patterns and use the Feed Audit / Explain SID tools after changes. SID tracking is a guardrail; semantic selectors are the more resilient primary selection layer.",
                ],"Advanced rule-selection control")
            elif ch == ord("s") and dirty:
                try:
                    apply_policy_changes(args.policy, {("rule_overrides", category, "semantic_keep"): selectors})
                    dirty=False
                    safe_addstr(stdscr, h-2, 2, "Semantic selectors saved.", color(2)); stdscr.refresh(); curses.napms(1000)
                except Exception as exc:
                    safe_addstr(stdscr, h-2, 2, f"Save failed: {exc}", color(4)); stdscr.refresh(); curses.napms(1400)


def _alert_threshold_profiles_editor(stdscr, args):
    while True:
        policy = load_policy(args.policy)
        profiles = get_path(policy, ("alert_tuning", "profiles"), {}) or {}
        items = [(name, f"{cfg.get('type')}  {cfg.get('track')}  count={cfg.get('count')} / {cfg.get('seconds')}s")
                 for name, cfg in profiles.items()]
        choice = choose_menu(
            stdscr,
            "Alert Tuning / Threshold Profiles",
            items,
            "Each profile controls how often a matching rule is allowed to alert; detection itself stays enabled.",
            [
                "THRESHOLD PROFILES",
                "",
                "limit: cap repeated alerts inside a time window.",
                "threshold: alert only after the configured number of matches.",
                "both: combine thresholding and limiting.",
                "",
                "These settings reduce alert volume; they do not disable the rule's detection/state actions.",
            ],
        )
        if not choice:
            return
        edit_settings(stdscr, args, f"Alert Tuning / {choice}", [
            Setting("Type", ("alert_tuning", "profiles", choice, "type"), "enum", ("limit", "threshold", "both"),
                    "How alert frequency is controlled."),
            Setting("Track", ("alert_tuning", "profiles", choice, "track"), "enum", ("by_src", "by_dst", "by_rule", "by_both", "by_flow"),
                    "What Suricata counts separately: source, destination, rule, src/dst pair, or flow."),
            Setting("Count", ("alert_tuning", "profiles", choice, "count"), "int",
                    help="Number of matches/alerts used by this threshold profile."),
            Setting("Seconds", ("alert_tuning", "profiles", choice, "seconds"), "int",
                    help="Time window in seconds for the configured Count."),
        ], "Detailed threshold values. The master switch is changed one level up.")


def alert_tuning_editor(stdscr, args, title: str = "Policy Editor / Alert Tuning"):
    """Alert-tuning overview with the master ON/OFF visually separated from details."""
    while True:
        policy = load_policy(args.policy)
        enabled = bool(get_path(policy, ("alert_tuning", "enabled"), False))
        profiles = get_path(policy, ("alert_tuning", "profiles"), {}) or {}
        suppressions = get_path(policy, ("alert_tuning", "suppressions"), []) or []
        items = [
            ("Master switch", "ON - noise controls are generated" if enabled else "OFF - no generated noise controls"),
            ("", "DETAILS"),
            ("Threshold profiles", f"{len(profiles)} configured profiles"),
            ("Suppressions", f"{len(suppressions)} reviewed suppression(s)"),
        ]
        details = {
            "Master switch": "ON enables generated threshold/suppression controls. OFF leaves alert volume untouched. Detection rules are not disabled by this switch.",
            "Threshold profiles": "Set count/time behavior for categories or SIDs that use alert tuning. This changes alert frequency, not whether the detection rule runs.",
            "Suppressions": "Reviewed exceptions that silence alerts for a specific SID/scope/IP. Use more carefully than thresholds because alerts can be hidden for that context.",
        }
        choice = choose_menu(
            stdscr, title, items,
            "Master ON/OFF is separate from the detailed threshold/suppression settings below.",
            [
                "ALERT TUNING",
                "",
                "This feature controls alert volume only. It does not turn detection rules off.",
                "Use Threshold profiles for repeated alert spam; use Suppressions only for reviewed exceptions.",
            ],
            show_selected_description=True, selected_detail_descriptions=details,
        )
        if not choice:
            return
        if choice == "Master switch":
            edit_settings(stdscr, args, "Alert Tuning / Master Switch", [
                Setting("Alert tuning", ("alert_tuning", "enabled"), help="ON generates configured noise-control thresholds/suppressions. OFF does not. Detection rules stay independent."),
            ], "This ON/OFF is the master control. Detailed limits are configured separately.")
        elif choice == "Threshold profiles":
            _alert_threshold_profiles_editor(stdscr, args)
        elif choice == "Suppressions":
            suppressions_editor(stdscr, args)


def suppressions_editor(stdscr, args):
    policy = load_policy(args.policy)
    vals = list(get_path(policy, ("alert_tuning", "suppressions"), []) or [])
    sel, dirty = 0, False
    while True:
        draw_header(stdscr, "Policy Editor / Suppressions", "a: add   e: edit   d: delete   s: save",
                    "q: Back   ↑↓: Navigate   a: Add   e: Edit   d: Delete   ?: Help   s: Save")
        h, _ = stdscr.getmaxyx(); page=max(4,h-7)
        if vals: sel=max(0,min(sel,len(vals)-1))
        top=max(0,sel-page+1)
        for row,idx in enumerate(range(top,min(len(vals),top+page))):
            v=vals[idx] if isinstance(vals[idx],dict) else {}
            text=f"SID={v.get('sid','?')}  track={v.get('track','?')}  ip={v.get('ip','-')}"
            safe_addstr(stdscr,4+row,3,text,curses.A_REVERSE if idx==sel else 0)
        if not vals: safe_addstr(stdscr,4,3,"(no suppressions)",curses.A_DIM)
        if dirty: safe_addstr(stdscr,2,55,"UNSAVED",color(3)|curses.A_BOLD)
        stdscr.refresh(); ch=stdscr.getch()
        if ch in (ord('q'),27):
            if not dirty or confirm(stdscr,"Discard unsaved suppression changes?"): return
        elif ch in (curses.KEY_UP,ord('k')) and vals: sel=(sel-1)%len(vals)
        elif ch in (curses.KEY_DOWN,ord('j')) and vals: sel=(sel+1)%len(vals)
        elif ch==ord('a'):
            sid=input_text(stdscr,"SID:")
            track=input_text(stdscr,"Track (by_src/by_dst/by_rule):","by_src")
            ip=input_text(stdscr,"IP/CIDR (optional):")
            try:
                if sid:
                    item={"sid":int(sid),"track":track or "by_src"}
                    if ip: item["ip"]=ip
                    vals.append(item); sel=len(vals)-1; dirty=True
            except ValueError: pass
        elif ch==ord('e') and vals:
            item=dict(vals[sel])
            sid=input_text(stdscr,"SID:",str(item.get("sid","")))
            track=input_text(stdscr,"Track:",str(item.get("track","by_src")))
            ip=input_text(stdscr,"IP/CIDR (blank removes):",str(item.get("ip","")))
            try:
                item["sid"]=int(sid); item["track"]=track or "by_src"
                if ip: item["ip"]=ip
                else: item.pop("ip",None)
                vals[sel]=item; dirty=True
            except (ValueError,TypeError): pass
        elif ch==ord('d') and vals and confirm(stdscr,"Delete this suppression?"):
            del vals[sel]; sel=max(0,sel-1); dirty=True
        elif _is_help_key(ch):
            text_viewer(stdscr,"Suppressions / Help",[
                "A suppression prevents alerts for a specific SID under the configured tracking scope/IP. It does not remove the detection rule itself.",
                "",
                "Use suppressions only for a known, reviewed false-positive or intentionally ignored source/destination. A broad suppression can hide a real alert.",
                "",
                "Risk: HIGH. Prefer threshold/rate limiting when you still want visibility but need less alert volume.",
            ],"Advanced alert-noise control")
        elif ch==ord('s') and dirty:
            try:
                apply_policy_changes(args.policy,{("alert_tuning","suppressions"):vals}); dirty=False
                safe_addstr(stdscr,h-2,2,f"Saved. Active Policy: {_active_policy_label(args.policy)}",color(2)); stdscr.refresh(); curses.napms(1200)
            except Exception as exc:
                safe_addstr(stdscr,h-2,2,f"Save failed: {exc}",color(4)); stdscr.refresh(); curses.napms(1400)


def validation_editor(stdscr, args):
    policy = load_policy(args.policy)
    helps = {
        "require_suricata_test": "Require a staged Suricata -T before an accepted tuned ruleset is promoted, even outside deployment. Recommended ON.",
        "check_flowbit_dependencies": "Verify that enabled rules requiring flowbits have compatible setter rules available/restored.",
        "check_xbit_dependencies": "Verify xbits cross-flow/host dependencies for enabled rules.",
        "require_ja3_fingerprinting": "When final-enabled rules use JA3/JA3S, fail only if JA3 is explicitly disabled or configuration state cannot be determined. An unset value is valid because Suricata can enable JA3 on demand.",
        "require_explicit_ja3_fingerprinting": "Strict JA3 mode. Require an explicit app-layer.protocols.tls.ja3-fingerprints: yes setting instead of accepting Suricata's on-demand auto-enable behavior.",
        "generate_diff_report": "Generate a rule-feed/tuning diff so new, removed and revised SIDs are visible between updates.",
    }
    settings=[]
    for key in (policy.get("validation",{}) or {}):
        settings.append(Setting(key.replace('_',' ').title(), ("validation",key), help=helps.get(key,"Pre-release validation/deployment safety control.")))
    edit_settings(stdscr,args,"Policy Editor / Validation",settings)


def advanced_mappings_editor(stdscr,args):
    policy=load_policy(args.policy)
    settings=[]
    # Selective-category actions are policy annotations used for review/reporting.
    for name,cfg in (policy.get("selective_categories",{}) or {}).items():
        settings.append(Setting(f"Selective {name}",("selective_categories",name,"action"),"text",help="Review/action annotation for this category."))
    # GPL prefix mapping is operational because it maps raw rule labels to logical policy categories.
    for raw,target in (policy.get("gpl_category_mapping",{}) or {}).items():
        settings.append(Setting(f"GPL mapping: {raw}",("gpl_category_mapping",raw),"text",help="Logical category used for this GPL prefix/subcategory."))
    edit_settings(stdscr,args,"Policy Editor / Advanced Mappings",settings,"Audit snapshot remains read-only because it is historical traceability data")


def standard_assets_editor(stdscr, args):
    """Daily-use compact asset overview; details are one Enter deeper."""
    assets_editor(stdscr, args, "Standard Settings / Assets")


def standard_organization_editor(stdscr, args):
    """Daily-use compact organization-policy overview."""
    organization_editor(stdscr, args, "Standard Settings / Organization Policy")

def standard_noise_editor(stdscr, args):
    alert_tuning_editor(stdscr, args, "Standard Settings / Alert Tuning")


def _policy_file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile_state_path(policy_path: Path) -> Path:
    return policy_path.with_name(".suricata-policy-engine-profile.json")


def _read_profile_state(policy_path: Path) -> dict:
    try:
        data = json.loads(_profile_state_path(policy_path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_profile_state(policy_path: Path, state: dict) -> None:
    target = _profile_state_path(policy_path)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)


def _record_active_profile(policy_path: Path, profile_name: str) -> None:
    _write_profile_state(policy_path, {
        "base_profile": profile_name,
        "profile": profile_name,  # backwards-compatible with v13 state files
        "custom": False,
        "policy_sha256": _policy_file_sha256(policy_path),
    })


def _profile_patch_matches(policy: dict, profile_cfg: dict) -> bool:
    changes = profile_cfg.get("changes", {}) or {}
    return bool(changes) and all(
        get_path(policy, tuple(path), object()) == value
        for path, value in changes.items()
    )


def _detect_profile_by_patch(policy: dict, profiles: dict) -> Optional[str]:
    matches: list[tuple[int, str]] = []
    for name, cfg in profiles.items():
        changes = cfg.get("changes", {}) or {}
        if _profile_patch_matches(policy, cfg):
            matches.append((len(changes), name))
    if not matches:
        return None
    matches.sort(reverse=True)
    return matches[0][1]


def _policy_state(policy_path: Path, policy: dict, profiles: dict) -> dict:
    """Describe the one effective policy shown by Standard and Advanced editors.

    A profile is only a preset/base. Once Standard or Advanced settings
    change the YAML, the effective policy becomes Custom (based on <profile>).
    """
    state = _read_profile_state(policy_path)
    base = str(state.get("base_profile") or state.get("profile") or "") or None
    stored_hash = state.get("policy_sha256")
    custom = bool(state.get("custom", False))
    current_hash = None
    try:
        current_hash = _policy_file_sha256(policy_path)
    except Exception:
        pass

    if base not in profiles:
        base = _detect_profile_by_patch(policy, profiles)
        custom = False
    elif stored_hash and current_hash and stored_hash != current_hash:
        # The YAML changed outside the TUI after the profile state was written.
        custom = True

    if base is None:
        return {"base_profile": None, "custom": True, "label": "Custom"}

    recommended = bool(profiles.get(base, {}).get("recommended"))
    base_label = base + (" Recommended" if recommended else "")
    if custom:
        label = f"Custom (based on {base_label})"
    else:
        label = base + (" (Recommended)" if recommended else "")
    return {"base_profile": base, "custom": custom, "label": label}


def _mark_policy_custom(policy_path: Path, base_profile: Optional[str] = None) -> None:
    state = _read_profile_state(policy_path)
    base = base_profile or state.get("base_profile") or state.get("profile")
    if not base:
        try:
            from profiles import PROFILES
            base = _detect_profile_by_patch(load_policy(policy_path), PROFILES)
        except Exception:
            base = None
    _write_profile_state(policy_path, {
        "base_profile": base,
        "profile": base,
        "custom": True,
        "policy_sha256": _policy_file_sha256(policy_path),
    })


def _detect_active_profile(policy_path: Path, policy: dict, profiles: dict) -> Optional[str]:
    """Return a profile pointer only while the effective policy is not Custom."""
    state = _policy_state(policy_path, policy, profiles)
    if state.get("custom"):
        return None
    return state.get("base_profile")


def _active_policy_label(policy_path: Path) -> str:
    try:
        from profiles import PROFILES
        return _policy_state(policy_path, load_policy(policy_path), PROFILES)["label"]
    except Exception:
        return "Unknown"


def _onoff(value) -> str:
    return "ON" if bool(value) else "OFF"


def _summary_scalar(value: Any) -> str:
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if isinstance(value, (list, tuple)) and all(not isinstance(x, (dict, list, tuple)) for x in value):
        return ", ".join(str(x) for x in value) if value else "None"
    return str(value)


def _append_summary_tree(lines: list[str], value: Any, indent: int = 2) -> None:
    """Append every leaf value so the pre-tune summary cannot silently omit a setting."""
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            lines.append(pad + "None")
            return
        for key, child in value.items():
            if isinstance(child, (dict, list, tuple)) and child:
                if isinstance(child, (list, tuple)) and all(not isinstance(x, (dict, list, tuple)) for x in child):
                    lines.append(f"{pad}{key}: {_summary_scalar(child)}")
                else:
                    lines.append(f"{pad}{key}:")
                    _append_summary_tree(lines, child, indent + 2)
            else:
                lines.append(f"{pad}{key}: {_summary_scalar(child)}")
        return
    if isinstance(value, (list, tuple)):
        if not value:
            lines.append(pad + "None")
            return
        for idx, child in enumerate(value, 1):
            if isinstance(child, (dict, list, tuple)):
                lines.append(f"{pad}[{idx}]")
                _append_summary_tree(lines, child, indent + 2)
            else:
                lines.append(f"{pad}- {_summary_scalar(child)}")
        return
    lines.append(pad + _summary_scalar(value))


def effective_policy_summary(policy_path: Path) -> list[str]:
    """Complete view of the effective policy; available on demand."""
    from profiles import PROFILES
    policy = load_policy(policy_path)
    state = _policy_state(policy_path, policy, PROFILES)
    lines = [
        f"ACTIVE POLICY: {state['label']}",
        f"Policy version: {policy.get('version', 'unknown')}   Name: {policy.get('name', 'unnamed')}",
        "",
        "Full execution detail. Profiles are presets; Standard/Advanced edits are already merged here.",
        "audit_snapshot is excluded because it is historical data, not an execution setting.",
    ]
    sections = [
        ("CATEGORY POLICY", "categories"),
        ("ASSETS / TECHNOLOGIES", "assets"),
        ("ORGANIZATION POLICY", "organization_policy"),
        ("ORGANIZATION POLICY SELECTORS", "organization_policy_selectors"),
        ("DEFAULTS & DEPENDENCIES", "defaults"),
        ("RULE OVERRIDES", "rule_overrides"),
        ("SEMANTIC / SELECTIVE CATEGORY LOGIC", "selective_categories"),
        ("ALERT TUNING", "alert_tuning"),
        ("TELEMETRY", "telemetry"),
        ("VALIDATION", "validation"),
        ("ADVANCED GPL MAPPINGS", "gpl_category_mapping"),
    ]
    for title, key in sections:
        lines += ["", title]
        _append_summary_tree(lines, policy.get(key, {}) or {}, 2)
    return lines


def concise_tune_summary(policy_path: Path) -> list[str]:
    """Short, decision-focused summary shown before tuning."""
    policy = load_policy(policy_path)
    cats = policy.get("categories", {}) or {}
    modes = {"preserve_feed": 0, "conditional": 0, "asset_based": 0, "disable": 0}
    for cfg in cats.values():
        mode = str((cfg or {}).get("mode", "unknown"))
        modes[mode] = modes.get(mode, 0) + 1

    assets = policy.get("assets", {}) or {}
    apps = assets.get("web_specific_apps", {}) or {}
    databases = assets.get("database_products", {}) or {}
    enabled_assets = [name for name, cfg in apps.items() if isinstance(cfg, dict) and cfg.get("enabled") is True]
    enabled_assets.extend(name for name, cfg in databases.items() if isinstance(cfg, dict) and cfg.get("enabled") is True)
    if (assets.get("web_server", {}) or {}).get("enabled"):
        enabled_assets.insert(0, "web_server")
    if (assets.get("scada", {}) or {}).get("enabled"):
        enabled_assets.append("scada")
    if (assets.get("voip", {}) or {}).get("enabled"):
        enabled_assets.append("voip")
    if (assets.get("activex", {}) or {}).get("enabled"):
        enabled_assets.append("activex")

    org = policy.get("organization_policy", {}) or {}
    def org_state(key: str) -> str:
        cfg = org.get(key, {}) or {}
        prohibited = cfg.get("prohibited")
        detect = cfg.get("detection_enabled")
        usage = "Prohibited" if prohibited is True else ("Allowed" if prohibited is False else "No usage decision")
        return f"{usage}; detect={'ON' if detect else 'OFF'}"

    defaults = policy.get("defaults", {}) or {}
    dep = (defaults.get("dependency_restore", {}) or {})
    alert = policy.get("alert_tuning", {}) or {}
    return [
        f"Active Policy : {_active_policy_label(policy_path)}",
        "",
        "CATEGORY POLICY",
        f"  Preserve feed : {modes.get('preserve_feed', 0)}",
        f"  Conditional   : {modes.get('conditional', 0)}",
        f"  Asset based   : {modes.get('asset_based', 0)}",
        f"  Disabled      : {modes.get('disable', 0)}",
        "",
        "ASSETS",
        f"  Enabled       : {', '.join(enabled_assets) if enabled_assets else 'None'}",
        "",
        "ORGANIZATION POLICY",
        f"  TOR           : {org_state('tor')}",
        f"  Remote access : {_remote_access_summary(org.get('remote_access', {}) or {})}",
        f"  P2P           : {org_state('p2p')}",
        "",
        "TUNING SAFETY",
        f"  Alert tuning  : {_onoff(alert.get('enabled'))}",
        f"  Dependencies  : {_onoff(dep.get('enabled'))}",
        "",
        "Press D for the complete effective-policy details.",
    ]


def compact_policy_summary(policy_path: Path) -> list[str]:
    """Very small dashboard summary of the effective policy."""
    policy = load_policy(policy_path)
    assets = policy.get("assets", {}) or {}
    apps = assets.get("web_specific_apps", {}) or {}
    databases = assets.get("database_products", {}) or {}
    enabled_assets = []
    for key in ("web_server", "scada", "voip", "activex"):
        if bool((assets.get(key, {}) or {}).get("enabled")):
            enabled_assets.append(ASSET_LABELS.get(key, key))
    for name, cfg in apps.items():
        if isinstance(cfg, dict) and cfg.get("enabled") is True:
            enabled_assets.append(ASSET_LABELS.get(name, name))
    for name, cfg in databases.items():
        if isinstance(cfg, dict) and cfg.get("enabled") is True:
            enabled_assets.append(ASSET_LABELS.get(name, name))

    org = policy.get("organization_policy", {}) or {}
    tor = org.get("tor", {}) or {}
    remote = org.get("remote_access", {}) or {}
    defaults = policy.get("defaults", {}) or {}
    dep = defaults.get("dependency_restore", {}) or {}
    alert = policy.get("alert_tuning", {}) or {}

    asset_text = ", ".join(enabled_assets[:5]) if enabled_assets else "None"
    if len(enabled_assets) > 5:
        asset_text += f" +{len(enabled_assets)-5} more"

    active_label = _active_policy_label(policy_path)
    lines = [
        f"Active Policy : {active_label}",
        f"Assets        : {asset_text}",
        f"Org policy    : TOR={_organization_policy_summary(tor.get('prohibited'), tor.get('detection_enabled'))}; "
        f"Remote Access={_remote_access_summary(remote)}",
        f"Unknown rules : {'DISABLE' if bool(defaults.get('disable_unknown_categories', False)) else 'PRESERVE FEED STATE'}",
        f"Safety        : Alert tuning={_onoff(alert.get('enabled'))}; Dependencies={_onoff(dep.get('enabled'))}",
    ]
    if active_label == "Raw":
        lines.append("Raw mode      : Pass-through only; use Advanced Settings for manual changes.")
    return lines


def confirm_tune_policy(stdscr, policy_path: Path) -> bool:
    """Show a concise effective-policy review and require explicit approval."""
    source_lines = [str(x) for x in concise_tune_summary(policy_path)]
    while True:
        draw_header(
            stdscr,
            "Review Policy Before Tuning",
            "A short summary of the policy that will be used for this tuning run.",
            "Enter/T: Start Tuning   D: Full Details   q/Esc: Back",
        )
        h, w = stdscr.getmaxyx()
        width = max(20, w - 6)
        rendered: list[str] = []
        for line in source_lines:
            if not line:
                rendered.append("")
                continue
            rendered.extend(textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False) or [""])
        page = max(4, h - 6)
        for row, line in enumerate(rendered[:page]):
            safe_addstr(stdscr, 4 + row, 3, line)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("t"), ord("T"), 10, 13):
            return True
        if ch in (ord("d"), ord("D")):
            text_viewer(stdscr, "Full Effective Policy", effective_policy_summary(policy_path), "Complete settings used by Tune My Rules")
            continue
        if ch in (ord("q"), 27):
            return False


def _profile_display_marker(profile_name: str, state: dict) -> str:
    """Return an unambiguous marker for the Profiles screen.

    ▶ means the profile itself is the active effective policy.
    ↳ means the profile is only the base of a Custom effective policy.
    """
    base = state.get("base_profile")
    if profile_name != base:
        return "  "
    return "↳ " if state.get("custom") else "▶ "


def profile_editor(stdscr, args):
    from profiles import PROFILES
    while True:
        policy = load_policy(args.policy)
        state = _policy_state(args.policy, policy, PROFILES)
        active = state.get("base_profile")
        items = []
        display_to_name: dict[str, str] = {}
        for name, cfg in PROFILES.items():
            label = name + (" (Recommended)" if cfg.get("recommended") else "")
            display = _profile_display_marker(name, state) + label
            items.append((display, cfg["description"]))
            display_to_name[display] = name
        if state.get("custom") and state.get("base_profile"):
            status = (
                f"Active Policy: {state['label']}  |  "
                f"↳ {state['base_profile']} is the BASE only; it is not the active effective policy."
            )
        else:
            status = f"Active Policy: {state['label']}  |  ▶ marks the active profile."
        choice_display = choose_menu(
            stdscr,
            "Standard Settings / Profiles",
            items,
            status,
        )
        if not choice_display:
            return
        choice = display_to_name[choice_display]
        cfg = PROFILES[choice]
        policy = load_policy(args.policy)
        lines = [choice + (" (Recommended)" if cfg.get("recommended") else ""), "", cfg["description"]]
        if choice == "Raw":
            lines += [
                "",
                "WARNING: Raw applies no automatic tuning policy.",
                "The Suricata feed state is passed through as-is until you make manual changes.",
                "Use Advanced Settings when you want to disable/enable specific categories, assets or overrides.",
            ]
        lines += ["", "Changes:"]
        changes = {}
        for path, value in cfg["changes"].items():
            old = get_path(policy, path, None)
            lines.append(f"  {'.'.join(path)}: {fmt_value(old)} -> {fmt_value(value)}")
            if old != value:
                changes[path] = value
        text_viewer(stdscr, f"Profile / {choice}", lines, "Preview profile values before applying")
        if not changes:
            _record_active_profile(args.policy, choice)
            text_viewer(stdscr, "Profile", [f"{choice} is already active.", "", "The pointer has been updated."])
            continue
        if confirm(stdscr, f"Apply profile '{choice}' ({len(changes)} changes)?"):
            try:
                backup = apply_policy_changes(args.policy, changes, source="profile")
                _record_active_profile(args.policy, choice)
                applied_lines = [f"Applied: {choice}", f"Backup: {backup}", "", "Run Tune My Rules to validate the new policy."]
                if choice == "Raw":
                    applied_lines += [
                        "",
                        "Raw is a pass-through starting point: the feed is not tuned automatically.",
                        "Go to Advanced Settings and define only the changes you actually want.",
                    ]
                text_viewer(stdscr, "Profile applied", applied_lines)
            except Exception as exc:
                text_viewer(stdscr, "Profile failed", [str(exc)])


def standard_policy_editor(stdscr, args):
    sections = [
        ("Profiles", "Raw, Balanced (Recommended), Noisy, Strict, Lab / Experimental and Server"),
        ("", ""),
        ("Assets & Technologies", "Manually define what actually exists in your monitored environment"),
        ("Organization Policy", "Usage-policy families including TOR, remote access, sharing, anonymizers and ET POLICY selectors"),
        ("Alert Tuning", "Control repeated-alert noise; master ON/OFF is separate from detailed limits"),
    ]
    while True:
        choice = choose_menu(stdscr, "Policy Editor / Standard Settings", sections,
                             "Recommended for normal day-to-day tuning")
        if not choice:
            return
        if choice == "Profiles":
            profile_editor(stdscr, args)
        elif choice == "Assets & Technologies":
            standard_assets_editor(stdscr, args)
        elif choice == "Organization Policy":
            standard_organization_editor(stdscr, args)
        elif choice == "Alert Tuning":
            standard_noise_editor(stdscr, args)


def advanced_settings_editor(stdscr, args):
    sections = [
        ("", "POLICY & ASSETS"),
        ("Category Policy", "Choose the base action for each rule category; conditional categories use a second decision."),
        ("Assets", "Tell the tuner which monitored technologies actually exist in your environment."),
        ("Organization Policy", "Define what usage is allowed or prohibited, separately from whether it should be detected."),
        ("", ""),
        ("", "DETECTION LOGIC"),
        ("Defaults & Dependencies", "Set safe fallback behavior and restore required flowbit/xbit dependencies."),
        ("Rule Overrides", "Manage tracked SIDs and explicit per-SID keep or force-enable exceptions."),
        ("Semantic Selectors", "Keep important detections by meaning when rule SIDs change or are replaced."),
        ("", ""),
        ("", "NOISE CONTROL"),
        ("Alert Tuning", "Reduce repetitive alerts with category or per-SID thresholds without disabling detection."),
        ("Suppressions", "Silence reviewed SID/IP alert cases without disabling the rule everywhere."),
        ("", ""),
        ("", "ENGINE & VALIDATION"),
        ("Validation", "Control pre-activation safety checks for rules, dependencies, JA3 and configuration."),
        ("Advanced Mappings", "Map legacy GPL/feed labels into the tuner categories used by this policy."),
    ]
    details = {
        "Category Policy": (
            "This is the main category-level decision layer. Mode answers: what should normally happen to this category? "
            "If Mode is CONDITIONAL, Strategy answers the second question: how should that conditional decision be resolved?"
        ),
        "Assets": (
            "What technologies do you actually have in the environment Suricata monitors? Turn them ON here. "
            "The tuner uses this inventory to keep relevant asset-specific detections; leave technologies you do not use OFF. "
            "Matcher thresholds, aliases and regexes are advanced fine-tuning controls one level deeper."
        ),
        "Organization Policy": (
            "Tell the tuner what activities your organization allows or prohibits, and separately whether Suricata should detect them. "
            "For example, TOR can be prohibited while TOR detection remains ON so the SOC still receives alerts."
        ),
        "Defaults & Dependencies": (
            "Controls conservative fallback behavior and dependency restoration. Required flowbit/xbit setter rules can be restored when an enabled detection depends on them."
        ),
        "Rule Overrides": (
            "Use this for precise SID-level exceptions and tracking. It is a guardrail for special cases, not the primary way the policy should classify large groups of rules."
        ),
        "Semantic Selectors": (
            "Defines meaning-based selectors for important detections, so a useful behavior can still be recognized if the feed revises or replaces its SID."
        ),
        "Alert Tuning": (
            "Controls alert-rate thresholds globally, by category, or for a specific SID. It reduces repetitive noise while keeping the detection rule enabled."
        ),
        "Suppressions": (
            "Use only for reviewed cases where a known SID/IP combination should stop alerting. Suppression hides alerts for that context; it does not remove the rule globally."
        ),
        "Validation": (
            "Defines safety checks that must pass before tuned rules can be activated, including syntax/config validation, dependency integrity and required JA3 behavior."
        ),
        "Advanced Mappings": (
            "Maintains compatibility mappings from legacy GPL or feed labels to the tuner's logical categories. Change this only when a feed label is not mapped correctly."
        ),
    }
    while True:
        choice = choose_menu(
            stdscr,
            "Policy Editor / Advanced Settings",
            sections,
            "Grouped by purpose. Select a section; ? shows contextual help inside editors.",
            show_selected_description=True,
            selected_detail_descriptions=details,
        )
        if not choice:
            return
        if choice == "Category Policy": _run_screen_safely(stdscr, "Category Policy", category_policy_editor, args)
        elif choice == "Assets": assets_editor(stdscr,args)
        elif choice == "Organization Policy": organization_editor(stdscr,args)
        elif choice == "Defaults & Dependencies": defaults_editor(stdscr,args)
        elif choice == "Rule Overrides": rule_override_editor(stdscr,args)
        elif choice == "Semantic Selectors": semantic_selector_editor(stdscr,args)
        elif choice == "Alert Tuning": alert_tuning_editor(stdscr,args)
        elif choice == "Suppressions": suppressions_editor(stdscr,args)
        elif choice == "Validation": validation_editor(stdscr,args)
        elif choice == "Advanced Mappings": advanced_mappings_editor(stdscr,args)


def policy_editor(stdscr, args):
    sections = [
        ("", "DAY-TO-DAY POLICY"),
        ("Standard Settings", "Recommended: profiles, assets, organization policy and basic noise control"),
        ("", ""),
        ("", "ADVANCED / EXPERT"),
        ("Advanced Settings", "Categories, dependencies, selectors, SID exceptions, thresholds and validation"),
    ]
    while True:
        active_label = _active_policy_label(args.policy)
        choice=choose_menu(
            stdscr,
            "Policy Editor",
            sections,
            f"ACTIVE POLICY: {active_label}  |  Standard and Advanced edit the same effective policy",
        )
        if not choice: return
        if choice=="Standard Settings":
            standard_policy_editor(stdscr,args)
        elif choice=="Advanced Settings":
            if advanced_settings_warning(stdscr):
                advanced_settings_editor(stdscr,args)


def read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def report_path_for(output: Path) -> Path:
    return default_state_dir() / "last-report.json"


def diff_path_for(output: Path) -> Path:
    return output.with_name("suricata-tuned.diff.txt")


def _state_path_for(output: Path) -> Path:
    return default_state_dir() / "ruleset-state.json"


def build_live_insights(args) -> dict:
    """Run the exact tuner decision engine in memory and build v10 insights."""
    import tune_rules as tuner
    import policy_insights as insights

    policy = tuner.core.load_policy(args.policy)
    rules = tuner.core.load_rules(args.rules)
    result = tuner.apply_policy(rules, policy)
    baseline = resolve_baseline(policy, args.policy)
    tracked_audit = tuner.audit_tracked_rules(rules, policy, baseline)
    current = tuner.current_state(rules, tuner.core.sha256_file(args.rules), tuner.core.sha256_file(args.policy))
    state_path = _state_path_for(args.output)
    previous = read_json(state_path) if state_path.exists() else None
    diff = tuner.compute_diff(previous, current)
    bundle = insights.insights_bundle(rules, policy, result, tracked_audit, diff, previous)
    return {
        "policy": policy,
        "rules": rules,
        "result": result,
        "tracked_audit": tracked_audit,
        "previous": previous,
        "diff": diff,
        "bundle": bundle,
    }


def recommendation_lines(recommendations: list[dict]) -> list[str]:
    lines = [
        "RECOMMENDATION ENGINE",
        "",
        "Recommendations are deterministic findings from the current policy, ruleset, dependency graph and tracked-SID state.",
        "They are not threat predictions and do not replace analyst review.",
        "",
    ]
    if not recommendations:
        return lines + ["No recommendations available."]
    for idx, rec in enumerate(recommendations, 1):
        lines.extend([
            f"{idx}. [{str(rec.get('severity','info')).upper()}] {rec.get('title','')}",
            f"Why: {rec.get('why','')}",
            f"Action: {rec.get('action','')}",
        ])
        ev = rec.get("evidence", {}) or {}
        if ev:
            compact = []
            for key, value in ev.items():
                if isinstance(value, list):
                    shown = ", ".join(str(x) for x in value[:20])
                    if len(value) > 20:
                        shown += f" ... (+{len(value)-20})"
                    compact.append(f"{key}=[{shown}]")
                else:
                    compact.append(f"{key}={value}")
            lines.append("Evidence: " + " | ".join(compact))
        lines.append("")
    return lines


def health_lines(health: dict) -> list[str]:
    lines = [
        "POLICY HEALTH CHECK",
        "",
        f"Configuration health: {health.get('score','?')}/100 ({health.get('status','UNKNOWN')})",
        health.get("note", ""),
        f"Actionable findings: {health.get('actionable_findings',0)}",
        "",
        "Checks:",
    ]
    for key, ok in (health.get("checks", {}) or {}).items():
        lines.append(f"  {'PASS' if ok else 'REVIEW':<7} {key.replace('_',' ')}")
    by = health.get("by_severity", {}) or {}
    if by:
        lines.extend(["", "Findings by severity: " + ", ".join(f"{k}={v}" for k,v in sorted(by.items()))])
    lines.extend([
        "",
        "Interpretation: this score measures internal policy/configuration consistency and integrity checks only.",
        "It is intentionally NOT a score for security coverage, detection quality, compromise likelihood or SOC maturity.",
    ])
    return lines


def impact_lines(impact: dict) -> list[str]:
    lines = ["UPDATE IMPACT PREVIEW", ""]
    if impact.get("baseline", True):
        lines.extend([
            "No previous tuner state exists yet.",
            "The next successful deployed/generated state will become the comparison baseline.",
        ])
        return lines
    rows = [
        ("New SIDs", impact.get("new_sids", 0)),
        ("New SIDs active after tuning", impact.get("new_final_enabled", 0)),
        ("Removed SIDs", impact.get("removed_sids", 0)),
        ("Removed SIDs previously active", impact.get("removed_were_enabled", 0)),
        ("REV changed", impact.get("rev_changed", 0)),
        ("Revised SIDs active after tuning", impact.get("revised_final_enabled", 0)),
        ("Existing SIDs newly enabled", impact.get("newly_enabled", 0)),
        ("Existing SIDs newly disabled", impact.get("newly_disabled", 0)),
        ("Changed SIDs needing review", impact.get("review_count", 0)),
    ]
    lines.extend(f"{label:<32}: {int(value):,}" for label, value in rows)
    review = impact.get("review_sids", []) or []
    if review:
        lines.extend(["", "Review SIDs:", "  " + ", ".join(str(x) for x in review[:80])])
        if len(review) > 80:
            lines.append(f"  ... (+{len(review)-80} more)")
    cats = impact.get("categories", {}) or {}
    if cats:
        lines.extend(["", "Affected categories:"])
        for cat, counts in list(cats.items())[:30]:
            lines.append(f"  {cat:<24} " + ", ".join(f"{k}={v}" for k,v in counts.items()))
    return lines


def rule_explorer_screen(stdscr, args):
    try:
        import tune_rules as tuner
        import rule_explorer
        policy = tuner.core.load_policy(args.policy)
        rules = tuner.core.load_rules(args.rules)
        tuner.apply_policy(rules, policy)
    except Exception as exc:
        text_viewer(stdscr, "Rule Explorer failed", [str(exc)])
        return
    query = input_text(stdscr, "Search query (e.g. cobalt, sid:2001294, category:ET_INFO, state:active):")
    if query is None:
        return
    while True:
        matches = rule_explorer.search_rules(rules, query, 500)
        if not matches:
            text_viewer(stdscr, "Rule Explorer", [f"Query: {query}", "", "No matching rules.", "",
                "Filters: sid:, category:, state:active|inactive|feed-active|feed-inactive|review, asset:, flowbit:, xbit:, cve:, meta:, reason:"])
        else:
            items = []
            for r in matches:
                state = "ON" if r.final_enabled else "OFF"
                items.append((str(r.sid), f"{state} rev={r.rev} {r.category or 'UNMAPPED'} | {r.msg[:100]}"))
            choice = choose_menu(stdscr, f"Rule Explorer / {query}", items,
                                 f"{len(matches)} match(es), capped at 500 | Enter explains SID | q returns")
            if choice:
                try:
                    sid = int(choice)
                    text_viewer(stdscr, f"Rule Explorer / Explain SID {sid}", build_sid_explanation(args, sid))
                except Exception as exc:
                    text_viewer(stdscr, "Explain failed", [str(exc)])
        if not confirm(stdscr, "Run another Rule Explorer search?"):
            return
        query = input_text(stdscr, "Search query:")
        if query is None:
            return


def history_screen(stdscr, args):
    import run_history
    hdir = run_history.default_history_dir(args.output)
    rows = run_history.list_runs(hdir)
    if not rows:
        text_viewer(stdscr, "Run History", [f"No historical runs found in {hdir}", "", "A snapshot is recorded after an accepted successful tuning run."])
        return
    items = []
    by_id = {}
    for row in rows:
        rid = str(row.get("run_id"))
        by_id[rid] = row
        sm = row.get("summary", {}) or {}
        items.append((rid, f"deploy={'yes' if row.get('deployed') else 'no'} test={'yes' if row.get('test_passed') else 'no'} final={sm.get('final_enabled','?')} health={sm.get('policy_health','?')}"))
    while True:
        choice = choose_menu(stdscr, "Run History", items, f"Snapshots: {hdir}")
        if not choice:
            return
        row = by_id[choice]
        sm = row.get("summary", {}) or {}
        lines = [
            f"Run: {choice}", f"Created: {row.get('created_at','')}",
            f"Deployed: {row.get('deployed')}", f"Suricata test passed: {row.get('test_passed')}", "",
            "Summary:",
        ]
        lines.extend(f"  {k}: {v}" for k, v in sm.items())
        lines.extend(["", "Artifacts:"])
        for k, v in (row.get("artifacts", {}) or {}).items():
            lines.append(f"  {k}: {v.get('name')}  sha256={str(v.get('sha256',''))[:16]}...")
        text_viewer(stdscr, "Run History / Details", lines)
        if os.geteuid() == 0 and confirm(stdscr, f"Rollback production to run {choice}?"):
            shell_out(stdscr, tuner_cmd(args, "--rollback", choice), "Safe Rollback")
            rows = run_history.list_runs(hdir)


def show_dashboard(stdscr, args):
    while True:
        draw_header(stdscr, "Dashboard", "Current effective policy",
                    "q: Back  p: History  r: Recs  h: Health  u: Impact  s: Explorer  y: History  b: Rollback  l: Live")
        report = read_json(report_path_for(args.output))
        try:
            policy = load_policy(args.policy)
        except Exception:
            policy = {}
        y = 4

        # One compact system-status line instead of four full paths.
        status_bits = [
            f"Rules={'OK' if args.rules.exists() else 'MISSING'}",
            f"Policy={'OK' if args.policy.exists() else 'MISSING'}",
            f"Config={'OK' if args.suricata_conf.exists() else 'MISSING'}",
            f"Tuned={'READY' if args.output.exists() else 'NONE'}",
        ]
        safe_addstr(stdscr, y, 2, "System status", color(1) | curses.A_BOLD); y += 1
        safe_addstr(stdscr, y, 4, "  ".join(status_bits)); y += 2

        try:
            safe_addstr(stdscr, y, 2, "Effective Policy", color(1) | curses.A_BOLD); y += 1
            for line in compact_policy_summary(args.policy):
                safe_addstr(stdscr, y, 4, line); y += 1
            safe_addstr(stdscr, y, 4, "Press p for tuning history.", curses.A_DIM); y += 2
        except Exception as exc:
            safe_addstr(stdscr, y, 2, f"Policy summary unavailable: {exc}", color(3)); y += 2

        cats = policy.get("categories", {}) or {}
        mode_counts = {}
        for cfg in cats.values():
            mode_counts[cfg.get("mode", "unknown")] = mode_counts.get(cfg.get("mode", "unknown"), 0) + 1
        safe_addstr(stdscr, y, 2, "Category Policy", color(1) | curses.A_BOLD); y += 1
        safe_addstr(stdscr, y, 4,
                    "  ".join(f"{k}={v}" for k, v in mode_counts.items())); y += 2

        disable_unknown = bool((policy.get("defaults", {}) or {}).get("disable_unknown_categories", False))
        safe_addstr(stdscr, y, 2, "Unmapped Rules", color(1) | curses.A_BOLD); y += 1
        if disable_unknown:
            safe_addstr(stdscr, y, 4, "Fallback: Disable rules not covered by policy.", color(3))
        else:
            safe_addstr(stdscr, y, 4, "Fallback: Follow feed state (leave unmatched rules unchanged).", color(2))
        y += 2

        safe_addstr(stdscr, y, 2, "!!! REMEMBER: A DISABLED RULE IS NOT NECESSARILY USELESS !!! ;)", color(3) | curses.A_BOLD)
        stdscr.refresh()
        ch=stdscr.getch()
        if ch in (ord('q'),27): return
        if ch==ord('p'):
            history_screen(stdscr,args)
            continue
        if ch in (ord('r'),ord('h'),ord('u')):
            source=report
            if not source or not source.get("policy_health"):
                try:
                    live=build_live_insights(args); bundle=live["bundle"]
                    source={"recommendations":bundle["recommendations"],"policy_health":bundle["policy_health"],"update_impact":bundle["update_impact"]}
                except Exception as exc:
                    text_viewer(stdscr,"Dashboard analysis error",[str(exc)]); continue
            if ch==ord('r'): text_viewer(stdscr,"Recommendations",recommendation_lines(source.get("recommendations",[]) or []))
            elif ch==ord('h'): text_viewer(stdscr,"Policy Health",health_lines(source.get("policy_health",{}) or {}))
            else: text_viewer(stdscr,"Update Impact",impact_lines(source.get("update_impact",{}) or {}))
        elif ch==ord('s'):
            rule_explorer_screen(stdscr,args)
        elif ch==ord('y'):
            history_screen(stdscr,args)
        elif ch==ord('b'):
            if os.geteuid()!=0:
                text_viewer(stdscr,"Safe Rollback",["Rollback changes production files and requires root/sudo."])
            else:
                history_screen(stdscr,args)
        elif ch==ord('l'):
            try:
                live=build_live_insights(args); bundle=live["bundle"]
                text_viewer(stdscr,"Live Policy Health",health_lines(bundle["policy_health"]),"Computed from the current feed and policy")
            except Exception as exc:
                text_viewer(stdscr,"Live analysis failed",[str(exc)])


def shell_out(stdscr, cmd: list[str], title: str):
    """Legacy interactive command runner retained for utility actions."""
    curses.def_prog_mode(); curses.endwin()
    print("\n"+"="*72); print(f" {title}"); print("="*72); print("$ "+" ".join(str(x) for x in cmd)); print()
    try: rc=subprocess.run(cmd).returncode
    except FileNotFoundError as exc: print(f"ERROR: {exc}"); rc=127
    print("\n"+("SUCCESS" if rc==0 else f"FAILED (exit {rc})"))
    input("\nPress Enter to return to the TUI...")
    curses.reset_prog_mode(); curses.curs_set(0); stdscr.refresh(); return rc


def _tune_stage(line: str, current: str) -> str:
    text = line.strip()
    stages = (
        ("[1/5]", "Loading policy"),
        ("[2/5]", "Parsing Suricata rules"),
        ("[3/5]", "Applying policy + dependencies"),
        ("[4/5]", "Writing tuned rules + alert policy"),
        ("[5/5]", "Writing audit + diff reports"),
        ("[TEST] Running", "Validating with suricata -T"),
        ("[TEST] PASS", "Suricata validation passed"),
        ("[DEPLOY] Installing", "Activating tuned rules"),
        ("[DEPLOY] Reloading", "Reloading Suricata rules"),
        ("[DEPLOY] PASS", "Tuned rules activated"),
        ("[ROLLBACK]", "Rollback / recovery"),
    )
    for needle, label in stages:
        if needle in text:
            return label
    return current


def _log_view_top(total: int, page: int, top: int, follow: bool) -> int:
    """Clamp an in-memory log viewport; follow=True pins it to the newest lines."""
    if follow:
        return max(0, total - page)
    return max(0, min(top, max(0, total - page)))


def _completed_log_viewer(stdscr, title: str, lines: list[str], rc: int, stage: str, elapsed: int) -> None:
    """Keep the complete command output readable in memory after a run finishes.

    Nothing is written to disk. The buffer exists only for the lifetime of this
    TUI process and is discarded when the process exits.
    """
    top = 0
    follow = True
    while True:
        h, _w = stdscr.getmaxyx()
        page = max(1, h - 11)
        top = _log_view_top(len(lines), page, top, follow)
        status = "SUCCESS" if rc == 0 else f"FAILED (exit {rc})"
        subtitle = f"{status}  |  Final stage: {stage}  |  Elapsed: {elapsed}s  |  {len(lines)} output lines"
        draw_header(
            stdscr,
            title,
            subtitle,
            "↑↓ / PgUp/PgDn: Scroll   Home/End: First/Latest   Enter or q: Close Output",
        )
        safe_addstr(stdscr, 4, 3, "Complete in-memory output:", curses.A_BOLD)
        if not lines:
            safe_addstr(stdscr, 6, 5, "(no output)", curses.A_DIM)
        else:
            visible = lines[top:top + page]
            for row, line in enumerate(visible):
                safe_addstr(stdscr, 6 + row, 5, line)
            safe_addstr(
                stdscr,
                3,
                max(2, _w - 30),
                f"Lines {top + 1}-{min(top + page, len(lines))}/{len(lines)}",
                curses.A_DIM,
            )
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (10, 13, ord("q"), 27):
            return
        if ch in (curses.KEY_UP, ord("k")):
            follow = False
            top -= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            follow = False
            top += 1
        elif ch == curses.KEY_PPAGE:
            follow = False
            top -= page
        elif ch == curses.KEY_NPAGE:
            follow = False
            top += page
        elif ch == curses.KEY_HOME:
            follow = False
            top = 0
        elif ch == curses.KEY_END:
            follow = True


def run_with_progress(stdscr, cmd: list[str], title: str) -> tuple[int, list[str]]:
    """Run a tuner command immediately and retain all output in RAM.

    During execution the user can scroll backward through output that has already
    arrived. End returns to live-follow mode. After completion the entire buffer
    remains scrollable until the user explicitly continues. No log file is
    created by this function.
    """
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError as exc:
        text_viewer(stdscr, title, [f"Could not start: {exc}"])
        return 127, [str(exc)]

    output_lines: list[str] = []
    stage = "Starting tuner"
    started = time.monotonic()
    spin = "|/-\\"
    spinner_idx = 0
    follow = True
    top = 0
    sel = selectors.DefaultSelector()
    assert proc.stdout is not None
    sel.register(proc.stdout, selectors.EVENT_READ)

    if hasattr(stdscr, "nodelay"):
        stdscr.nodelay(True)
    try:
        while True:
            events = sel.select(timeout=0.12)
            for key, _mask in events:
                line = key.fileobj.readline()
                if line:
                    clean = line.rstrip("\n")
                    output_lines.append(clean)
                    stage = _tune_stage(clean, stage)

            if proc.poll() is not None:
                # Drain output buffered after process exit.
                rest = proc.stdout.read()
                if rest:
                    for line in rest.splitlines():
                        output_lines.append(line)
                        stage = _tune_stage(line, stage)
                break

            h, _w = stdscr.getmaxyx()
            page = max(1, h - 12)
            top = _log_view_top(len(output_lines), page, top, follow)
            unseen = max(0, len(output_lines) - (top + page))
            footer = "↑↓ / PgUp/PgDn: Scroll   End: Follow live"
            if not follow and unseen:
                footer += f"   |   {unseen} newer line(s)"
            draw_header(
                stdscr,
                title,
                "Running now — full output is retained in memory.",
                footer,
            )
            elapsed = int(time.monotonic() - started)
            safe_addstr(stdscr, 4, 3, f"{spin[spinner_idx % len(spin)]}  {stage}", color(1) | curses.A_BOLD)
            safe_addstr(stdscr, 5, 3, f"Elapsed: {elapsed}s", curses.A_DIM)
            safe_addstr(stdscr, 7, 3, "Output:", curses.A_BOLD)
            if output_lines:
                for row, line in enumerate(output_lines[top:top + page]):
                    safe_addstr(stdscr, 8 + row, 5, line)
            else:
                safe_addstr(stdscr, 8, 5, "Waiting for tuner output...", curses.A_DIM)
            stdscr.refresh()
            spinner_idx += 1

            # Non-blocking navigation while the child keeps running.
            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1
            if ch in (curses.KEY_UP, ord("k")):
                follow = False
                top -= 1
            elif ch in (curses.KEY_DOWN, ord("j")):
                follow = False
                top += 1
            elif ch == curses.KEY_PPAGE:
                follow = False
                top -= page
            elif ch == curses.KEY_NPAGE:
                follow = False
                top += page
            elif ch == curses.KEY_HOME:
                follow = False
                top = 0
            elif ch == curses.KEY_END:
                follow = True
    finally:
        if hasattr(stdscr, "nodelay"):
            stdscr.nodelay(False)
        try:
            sel.close()
        except Exception:
            pass

    rc = proc.returncode or 0
    return rc, output_lines


def _tuning_result_lines(report: dict | None) -> list[tuple[str, str]]:
    report = report or {}
    before = report.get("feed_enabled_before_tuning", report.get("source_enabled_rules", 0)) or 0
    final = report.get("final_enabled_rules", 0) or 0
    return [
        ("Feed active", f"{int(before):,}"),
        ("Final active", f"{int(final):,}"),
        ("Reduced by", f"{max(int(before) - int(final), 0):,}"),
        ("Flowbits restored", f"{int(report.get('flowbit_dependency_sids_restored', 0) or 0):,}"),
        ("Xbits restored", f"{int(report.get('xbit_dependency_sids_restored', 0) or 0):,}"),
    ]


def production_choice(stdscr, original_rules: Path, tuned_rules: Path, report: dict | None = None, log_lines: list[str] | None = None) -> str:
    """Compact post-validation result screen with details/logs available on demand."""
    log_lines = log_lines or []
    while True:
        draw_header(
            stdscr,
            "Tuning Completed",
            "Tuned rules passed Suricata validation and are ready.",
            "A: Activate   K/Enter: Keep   R: ! Replace Original   L: View Full Log",
        )
        y = 4
        safe_addstr(stdscr, y, 3, "RESULT", color(1) | curses.A_BOLD); y += 2
        for label, value in _tuning_result_lines(report):
            safe_addstr(stdscr, y, 5, f"{label:<19}: {value}"); y += 1
        safe_addstr(stdscr, y, 5, "Validation         : PASS", color(2) | curses.A_BOLD); y += 2

        safe_addstr(stdscr, y, 3, "WHAT NEXT?", color(1) | curses.A_BOLD); y += 2
        safe_addstr(stdscr, y, 5, "[K] Keep Without Activating", curses.A_BOLD); y += 1
        safe_addstr(stdscr, y, 9, "Keep the tuned file for review; running Suricata is unchanged.", curses.A_DIM); y += 2

        safe_addstr(stdscr, y, 5, "[A] Activate Tuned Rules  (Recommended)", color(2) | curses.A_BOLD); y += 1
        safe_addstr(stdscr, y, 9, "Make the running Suricata use suricata-tuned.rules now.", curses.A_DIM); y += 1
        safe_addstr(stdscr, y, 9, "suricata.rules is NOT changed.", curses.A_DIM); y += 1
        safe_addstr(stdscr, y, 9, "Success is shown only if live Suricata reloads/restarts correctly.", curses.A_DIM); y += 2

        safe_addstr(stdscr, y, 5, "[R] ! Replace Original Rules  (! DESTRUCTIVE)", color(3) | curses.A_BOLD); y += 1
        safe_addstr(stdscr, y, 9, "Overwrite suricata.rules itself with the tuned content.", curses.A_DIM); y += 1
        safe_addstr(stdscr, y, 9, "Unlike Activate, this changes the original feed file. A backup is created first.", curses.A_DIM); y += 2

        if log_lines:
            safe_addstr(stdscr, y, 5, "[L] View Full In-Memory Log", curses.A_BOLD)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("l"), ord("L")) and log_lines:
            text_viewer(stdscr, "Tune My Rules / Full Log", log_lines, "Complete output retained in memory for this run")
            continue
        if ch in (ord("a"), ord("A")):
            return "activate"
        if ch in (ord("r"), ord("R")):
            return "replace"
        if ch in (ord("k"), ord("K"), ord("n"), ord("N"), 10, 13, ord("q"), 27):
            return "keep"


def confirm_activation(stdscr, original_rules: Path, tuned_rules: Path) -> bool:
    """Backward-compatible helper retained for tests/integrations."""
    return production_choice(stdscr, original_rules, tuned_rules) == "activate"


def tuner_cmd(args,*extra:str)->list[str]:
    cmd=[sys.executable,str(SCRIPT_DIR/"tune_rules.py"),"--rules",str(args.rules),"--policy",str(args.policy),"--output",str(args.output),"--suricata-conf",str(args.suricata_conf)]
    cmd.extend(extra); return cmd


def tune_rules_action(stdscr,args):
    """Review the effective policy, then tune with full in-memory progress output."""
    if not confirm_tune_policy(stdscr, Path(args.policy)):
        return

    rc, tune_log = run_with_progress(
        stdscr,
        tuner_cmd(args,"--test","--no-state-update"),
        "Tune My Rules / Validation",
    )
    if rc != 0:
        while True:
            draw_header(stdscr, "Tuning Failed", "Tuning or Suricata validation failed; production was not changed.", "L: View Full Log   Enter/q: Back")
            safe_addstr(stdscr, 5, 4, "Validation: FAILED", color(4) | curses.A_BOLD)
            safe_addstr(stdscr, 7, 4, "No tuned rules were activated.")
            safe_addstr(stdscr, 8, 4, "Press L to inspect the complete in-memory output.", curses.A_DIM)
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (ord("l"), ord("L")):
                text_viewer(stdscr, "Tune My Rules / Full Log", tune_log, "Failed tuning run")
                continue
            if ch in (10, 13, ord("q"), 27):
                return

    if os.geteuid() != 0:
        text_viewer(stdscr, "Tune My Rules", [
            "Tune + validation passed.",
            "",
            "Activation was not offered because the TUI is not running as root.",
            "Your original suricata.rules was not modified.",
            "Run the TUI with sudo when you want to activate suricata-tuned.rules.",
        ])
        return

    choice = production_choice(
        stdscr, Path(args.rules), Path(args.output),
        read_json(report_path_for(args.output)), tune_log,
    )
    if choice == "activate":
        activate_rc, activate_log = run_with_progress(
            stdscr, tuner_cmd(args,"--deploy"), "Activate Tuned Rules",
        )
        live = any("[DEPLOY] LIVE:" in line for line in activate_log)
        staged = any("[DEPLOY] STAGED:" in line for line in activate_log)
        if activate_rc == 0 and live:
            text_viewer(stdscr, "Activate Tuned Rules", [
                "LIVE SWITCH COMPLETED.",
                "",
                f"Active rule-files target: {args.output}",
                f"Configuration: {args.suricata_conf}",
                "The original suricata.rules feed file remains untouched.",
                "A blocking reload or service restart completed successfully.",
            ])
        elif activate_rc == 0 and staged:
            text_viewer(stdscr, "Activate Tuned Rules", [
                "CONFIG UPDATED, BUT NOT LIVE YET.",
                "",
                f"Suricata is configured to use: {args.output}",
                "No running Suricata instance was available to reload.",
                "Start/restart Suricata to make the tuned rules active.",
                "The original suricata.rules feed file remains untouched.",
            ])
        elif activate_rc == 0:
            text_viewer(stdscr, "Activate Tuned Rules", [
                "Production configuration was updated.",
                "",
                f"Configured rule-files target: {args.output}",
                "The activation command completed without an explicit live-verification marker.",
                "Review the in-memory activation output before assuming the running engine switched.",
            ])
        else:
            text_viewer(stdscr, "Activate Tuned Rules", [
                "ACTIVATION DID NOT SWITCH THE LIVE ENGINE.",
                "",
                "No success state was claimed. Configuration/artifacts were rolled back when required.",
                "Common causes are a running Suricata process pinned to another rules file with -S or using a different -c config.",
                "Review the complete in-memory activation output for the exact reason.",
            ])
    elif choice == "replace":
        if not confirm(stdscr, "! Replace original suricata.rules? This is NOT RECOMMENDED."):
            text_viewer(stdscr, "Tune My Rules", [
                "Original-rules replacement cancelled.",
                "",
                "The validated tuned rules are still available without changing production.",
            ])
            return
        replace_rc, replace_log = run_with_progress(
            stdscr, tuner_cmd(args,"--replace-original"), "Replace Original Rules (! Destructive)",
        )
        overwritten = any("[REPLACE] FILE OVERWRITTEN:" in line for line in replace_log)
        live = any("[REPLACE] LIVE:" in line for line in replace_log)
        if replace_rc == 0 and overwritten:
            lines = [
                "suricata.rules was overwritten with the validated tuned rules.",
                "",
                "A backup was created first and the installed file was SHA256-verified.",
            ]
            if live:
                lines.append("The running Suricata engine was reloaded/restarted successfully.")
            else:
                lines.append("The file replacement is complete; live reload was skipped or not required.")
            lines += ["", "A future suricata-update will replace suricata.rules with a fresh feed; tune again afterwards."]
            text_viewer(stdscr, "Original Rules Replaced", lines)
        elif replace_rc == 28 and overwritten:
            text_viewer(stdscr, "Original Rules Replaced / Reload Failed", [
                "suricata.rules WAS overwritten and passed Suricata validation.",
                "",
                "The live reload/restart failed, so the running process may still be using the previous in-memory ruleset.",
                "Restart/reload Suricata manually when ready.",
                "The validated replacement file was intentionally left in place.",
            ])
        else:
            text_viewer(stdscr, "Original Rules Replacement Failed", [
                "suricata.rules was not left in a partially replaced state.",
                "",
                "The engine restored the original file/config after a validation or installation failure.",
                "Review the complete in-memory output shown for this operation.",
            ])
    else:
        text_viewer(stdscr, "Tune My Rules", [
            "Tune + validation passed.",
            "",
            "The tuned rules were kept without activating them.",
            "Your original suricata.rules remains unchanged and active configuration was not switched by this action.",
        ])

def resolve_baseline(policy: dict, policy_path: Path | None = None) -> Path:
    """Resolve tracked baseline correctly for both source trees and pipx installs.

    The policy stores a portable relative filename.  In an installed wheel the
    baseline is materialized under the user's config directory, not beside tui.py.
    Prefer that packaged/materialized default when names match; then fall back to
    a baseline beside an explicitly supplied policy file.
    """
    for cfg in (policy.get("rule_overrides",{}) or {}).values():
        rel = get_path(cfg, ("tracked_sid_policy", "baseline_file"), None)
        if not rel:
            continue
        p = Path(str(rel)).expanduser()
        if p.is_absolute():
            return p
        if p.name == DEFAULT_TRACKED_BASELINE.name:
            return DEFAULT_TRACKED_BASELINE
        if policy_path is not None:
            beside_policy = Path(policy_path).expanduser().resolve().parent / p
            if beside_policy.exists():
                return beside_policy
        beside_script = SCRIPT_DIR / p
        if beside_script.exists():
            return beside_script
        return (Path(policy_path).expanduser().resolve().parent / p) if policy_path else DEFAULT_TRACKED_BASELINE
    return DEFAULT_TRACKED_BASELINE


def _force_enable_sids(policy: dict) -> set[int]:
    out: set[int] = set()
    for cfg in (policy.get("rule_overrides", {}) or {}).values():
        for sid in cfg.get("force_enable_sids", []) or []:
            try:
                out.add(int(sid))
            except (TypeError, ValueError):
                pass
    return out


def _matched_semantic_selectors(rule, policy: dict, tuner) -> list[str]:
    names: list[str] = []
    cfg = (policy.get("rule_overrides", {}) or {}).get(rule.category, {}) or {}
    selectors = cfg.get("semantic_keep", []) or []
    if isinstance(selectors, dict):
        selectors = [selectors]
    for idx, selector in enumerate(selectors):
        try:
            if tuner.core.selector_matches(rule, selector):
                names.append(str(selector.get("name") or f"selector-{idx+1}"))
        except Exception:
            continue
    return names


def _reason_text(rule) -> str:
    base = (rule.reason or "").split("+", 1)[0]
    mapping = {
        "preserve_feed_state": "The category preserves the rule feed's enabled/disabled state.",
        "category_disable": "The category is intentionally disabled by policy.",
        "asset_enabled": "The related asset/technology is marked as present, so the feed state is preserved.",
        "asset_disabled": "The related asset/technology is not marked as present, so the rule is disabled.",
        "asset_web_app_no_enabled_assets": "No enabled web-application asset could match this rule.",
        "conditional_org_enabled": "Organization policy requests detection for this activity, so the feed state is preserved.",
        "conditional_disabled_by_default": "This category is disabled by default and organization policy did not enable detection.",
        "remote_access_detection_enabled": "Remote-access detection is enabled by organization policy.",
        "remote_access_detection_disabled": "Remote-access detection is disabled by organization policy.",
        "conditional_default_disabled": "This category starts disabled; only semantic/SID exceptions or required dependencies can restore rules.",
        "enabled_by_default": "This conditional category keeps feed-enabled rules active by default.",
        "enabled_by_default_with_alert_tuning": "This category keeps feed-enabled rules active and can apply alert-rate tuning.",
        "message_filter_preserve_feed": "No configured message filter matched; the feed state is preserved.",
        "unknown_category_preserve_upstream": "The category is unknown to policy, so the safer fallback preserves the feed state.",
        "unknown_category_disabled": "Unknown categories are configured to be disabled.",
        "selective_preserve_upstream_pending_review": "Selective policy has no narrower decision, so the feed state is preserved pending review.",
        "organization_policy_selective_preserve_upstream": "No reviewed Organization Policy selector matched this mixed ET POLICY rule, so the upstream feed state is preserved.",
    }
    if base.startswith("asset_match:"):
        return "The asset matcher found a configured product with enough confidence to preserve the feed state."
    if base.startswith("asset_review:"):
        return "The asset matcher found partial evidence, but not enough confidence to enable the rule automatically."
    if base.startswith("asset_web_app_not_matched:"):
        return "The rule did not reach the configured confidence threshold for any enabled web application."
    if base.startswith("organization_policy_selective_enabled:"):
        return "A reviewed ET POLICY semantic family matched and Organization Policy requests detection; the upstream feed state is preserved."
    if base.startswith("organization_policy_selective_disabled:"):
        return "A reviewed ET POLICY semantic family matched and Organization Policy disables that usage-policy detection."
    if base.startswith("organization_policy_selector_ambiguous_preserve_upstream:"):
        return "Multiple Organization Policy selectors matched with conflicting detection decisions, so the safer upstream state is preserved for review."
    if base.startswith("message_filter_disable"):
        return "A configured message filter explicitly disabled this rule."
    return mapping.get(base, "The result comes from the category policy plus any semantic, SID, asset, or dependency overrides shown below.")


def build_sid_explanation(args, sid: int) -> list[str]:
    """Explain a SID with a deterministic step-by-step trace of the real policy engine."""
    try:
        import tune_rules as tuner
    except Exception as exc:
        return [f"Cannot import tuner core: {exc}"]

    try:
        policy = tuner.core.load_policy(args.policy)
        rules = tuner.core.load_rules(args.rules)
    except Exception as exc:
        return [f"Cannot load policy/rules: {exc}"]

    for r in rules.values():
        r.category = tuner.core.map_category(r.msg, policy)
    baseline_path = resolve_baseline(policy, args.policy)
    baseline_data = read_json(baseline_path) or {}
    baseline_entry = (baseline_data.get("tracked_rules", {}) or {}).get(str(sid))

    if sid not in rules:
        lines = [f"SID {sid}", "", "Current feed state: MISSING"]
        if baseline_entry:
            lines.extend([
                "Tracked baseline: YES",
                f"Last baseline REV: {baseline_entry.get('rev', '?')}",
                f"Last category: {baseline_entry.get('category', '?')}",
                f"Last message: {baseline_entry.get('msg', '?')}",
                "",
                "WHAT THIS MEANS",
                "The exact SID disappeared from the current feed. This does not automatically mean the detection disappeared: semantic selectors can still keep a replacement rule with a different SID.",
                "Review semantic replacements and the feed change before accepting a new tracked baseline.",
            ])
        else:
            lines.extend([
                "Tracked baseline: NO",
                "Explanation: the SID is not present in the current ruleset and is not known by the tracked baseline.",
            ])
        return lines

    # Capture the base category decision before semantic/SID/dependency overrides.
    rule = rules[sid]
    base_enabled, base_reason = tuner.core.base_policy_decision(rule, policy, Counter())

    # Run the exact production policy engine for final state and dependency restoration.
    result = tuner.apply_policy(rules, policy)
    rule = rules[sid]
    audit = tuner.audit_tracked_rules(rules, policy, baseline_path)
    tracked = sid in tuner.tracked_sid_set(policy)
    force_enabled = sid in _force_enable_sids(policy)
    semantic_names = _matched_semantic_selectors(rule, policy, tuner)
    category_cfg = (policy.get("categories", {}) or {}).get(rule.category, {}) or {}
    mode = category_cfg.get("mode", "unmapped")
    strategy = category_cfg.get("strategy", "-")

    drift_labels = []
    for key, label in (
        ("rev_changed", "REV changed"),
        ("logic_changed", "Detection logic changed"),
        ("message_changed", "Message changed"),
        ("category_changed", "Category changed"),
        ("missing", "Missing"),
        ("feed_disabled", "Feed disabled"),
    ):
        if sid in (audit.get(key, []) or []):
            drift_labels.append(label)

    classtype_m = re.search(r"\bclasstype\s*:\s*([^;]+);", rule.raw, re.I)
    refs = re.findall(r"\breference\s*:\s*([^;]+);", rule.raw, re.I)
    action_m = re.match(r"^\s*(\w+)", rule.raw)
    action = action_m.group(1).upper() if action_m else "?"

    # Dependency evidence: show both producers and consumers, not just bit names.
    flow_setters, _xbit_name_setters = tuner.core.dependency_indexes(rules)
    xbit_scope_setters = tuner.core.xbit_dependency_index(rules)
    flow_producers = {name: sorted(flow_setters.get(name, set())) for name in rule.flow_get}
    xbit_refs = rule.xbit_get_refs or {tuner.core.XbitRef(name=n) for n in rule.xbit_get}
    xbit_producers = {ref.label(): sorted(xbit_scope_setters.get((ref.name, ref.scope), set())) for ref in xbit_refs}
    flow_consumers = {}
    for name in rule.flow_set:
        flow_consumers[name] = sorted(r.sid for r in rules.values() if r.final_enabled and name in r.flow_get)
    xbit_consumers = {}
    setter_refs = rule.xbit_set_refs or {tuner.core.XbitRef(name=n) for n in rule.xbit_set}
    for ref in setter_refs:
        consumers = []
        for candidate in rules.values():
            if not candidate.final_enabled:
                continue
            reqs = candidate.xbit_get_refs or {tuner.core.XbitRef(name=n) for n in candidate.xbit_get}
            if any(req.name == ref.name and req.scope == ref.scope for req in reqs):
                consumers.append(candidate.sid)
        xbit_consumers[ref.label()] = sorted(consumers)

    lines = [
        f"SID {sid}  |  REV {rule.rev}",
        "",
        f"Message: {rule.msg or '(no msg)'}",
        f"Rule action: {action}",
        f"Feed state: {'ACTIVE' if rule.source_enabled else 'INACTIVE'}",
        f"Final tuner state: {'ACTIVE' if rule.final_enabled else 'INACTIVE'}",
        "",
        "WHY THIS STATE? -- DECISION TRACE",
        f"1. Feed -> {'ACTIVE' if rule.source_enabled else 'INACTIVE'}",
        f"2. Category mapping -> {rule.category or 'UNMAPPED'}",
        f"3. Base policy -> {'ACTIVE' if base_enabled else 'INACTIVE'} ({base_reason})",
    ]
    step = 4
    if semantic_names:
        lines.append(f"{step}. Semantic selector -> MATCH ({', '.join(semantic_names)}) -> eligible to stay/return ACTIVE")
        step += 1
    else:
        lines.append(f"{step}. Semantic selector -> no match")
        step += 1
    if tracked:
        tracked_effect = "kept if feed-enabled" if rule.source_enabled else "tracked only; feed-disabled rule is not resurrected"
        lines.append(f"{step}. Tracked SID guardrail -> YES ({tracked_effect})")
        step += 1
    if force_enabled:
        lines.append(f"{step}. Force-enable exception -> YES")
        step += 1
    if rule.restored_dependency_types:
        lines.append(f"{step}. Dependency resolver -> RESTORED ({', '.join(sorted(rule.restored_dependency_types))})")
        step += 1
    lines.append(f"{step}. FINAL -> {'ACTIVE' if rule.final_enabled else 'INACTIVE'}")

    lines.extend([
        "",
        "POLICY CONTEXT",
        f"Logical category: {rule.category or 'UNMAPPED'}",
        f"Policy path: categories.{rule.category or 'UNMAPPED'}",
        f"Mode: {mode}",
        f"Strategy: {strategy}",
        f"Reason code: {rule.reason or '-'}",
        f"Final reason code: {rule.reason or '-'}",
        f"Human explanation: {_reason_text(rule)}",
    ])
    if rule.category in (policy.get("rule_overrides", {}) or {}):
        lines.append(f"Override path: rule_overrides.{rule.category}")

    if semantic_names or tracked or force_enabled or rule.restored_dependency_types:
        lines.extend(["", "OVERRIDES / RESTORATION"])
        lines.append(f"Semantic selector match: {', '.join(semantic_names) if semantic_names else 'NO'}")
        lines.append(f"Tracked SID guardrail: {'YES' if tracked else 'NO'}")
        lines.append(f"Force-enable exception: {'YES' if force_enabled else 'NO'}")
        lines.append(f"Dependency restored: {', '.join(sorted(rule.restored_dependency_types)) if rule.restored_dependency_types else 'NO'}")

    if rule.asset_match_asset or rule.asset_review_candidate or rule.category == "ET_WEB_SPECIFIC_APPS":
        lines.extend([
            "",
            "ASSET MATCHING",
            f"Matched asset: {rule.asset_match_asset or 'NONE'}",
            f"Confidence score: {rule.asset_match_score}",
            f"Review candidate: {'YES' if rule.asset_review_candidate else 'NO'}",
            f"Evidence: {', '.join(rule.asset_match_evidence) if rule.asset_match_evidence else 'none'}",
        ])

    lines.extend(["", "STATEFUL DEPENDENCIES"])
    lines.append(f"flowbits sets: {', '.join(sorted(rule.flow_set)) if rule.flow_set else '-'}")
    for name, consumers in flow_consumers.items():
        lines.append(f"  -> enabled consumers of {name}: {', '.join(map(str,consumers[:30])) if consumers else 'none'}")
    flow_groups = ["|".join(sorted(g)) for g in rule.flow_get_groups] if rule.flow_get_groups else sorted(rule.flow_get)
    lines.append(f"flowbits requires (isset): {', '.join(flow_groups) if flow_groups else '-'}")
    for name, producers in flow_producers.items():
        lines.append(f"  <- available setters of {name}: {', '.join(map(str,producers[:30])) if producers else 'MISSING'}")
    xset_labels = sorted(ref.label() for ref in setter_refs)
    lines.append(f"xbits sets: {', '.join(xset_labels) if xset_labels else '-'}")
    for name, consumers in xbit_consumers.items():
        lines.append(f"  -> enabled consumers of {name}: {', '.join(map(str,consumers[:30])) if consumers else 'none'}")
    xget_labels = sorted(ref.label() for ref in xbit_refs)
    lines.append(f"xbits requires (isset): {', '.join(xget_labels) if xget_labels else '-'}")
    for name, producers in xbit_producers.items():
        lines.append(f"  <- compatible setters of {name}: {', '.join(map(str,producers[:30])) if producers else 'MISSING'}")

    lines.extend(["", "TRACKED SID INTEGRITY"])
    lines.append(f"Tracked: {'YES' if tracked else 'NO'}")
    lines.append(f"Baseline file: {baseline_path}")
    lines.append(f"Drift status: {', '.join(drift_labels) if drift_labels else ('OK' if tracked and baseline_entry else 'NOT TRACKED')}")
    if baseline_entry:
        lines.append(f"Baseline REV: {baseline_entry.get('rev', '?')}")
        lines.append(f"Current logic SHA256: {tuner.core.rule_logic_sha256(rule.raw)}")
        lines.append(f"Baseline logic SHA256: {baseline_entry.get('logic_sha256', '?')}")

    lines.extend(["", "WHAT WOULD CHANGE THIS DECISION?"])
    base = (rule.reason or "").split("+", 1)[0]
    if not rule.source_enabled and not force_enabled:
        lines.append("- The feed currently disables this SID. The tuner deliberately does not resurrect it unless it is a required dependency or an explicit force-enable exception.")
    if base in {"asset_disabled", "asset_web_app_no_enabled_assets"} or base.startswith("asset_web_app_not_matched") or base.startswith("asset_review"):
        lines.append("- Mark the real asset as present or improve precise metadata/alias/regex evidence. Avoid lowering global match thresholds just to force a match.")
    if base in {"conditional_disabled_by_default", "remote_access_detection_disabled"}:
        lines.append("- Change the corresponding organization_policy.*.detection_enabled decision if the organization wants visibility for this activity.")
    if base == "category_disable":
        lines.append("- Change the category mode from disable only if the organization intentionally wants these detections active.")
    if base == "conditional_default_disabled" and not semantic_names:
        lines.append("- A reviewed semantic selector or tracked exception can preserve a specific high-value detection without enabling the entire category.")
    if base == "conditional_default_disabled" and semantic_names:
        lines.append("- This category is normally OFF; the matched semantic selector is a direct reason this detection is preserved. Removing/changing that selector can disable it on the next tune.")
    if tracked and rule.source_enabled:
        lines.append("- This SID is also a tracked guardrail. If the feed disables or removes it, the tuner will warn rather than silently force it on; semantic replacement logic is then reviewed separately.")
    if force_enabled:
        lines.append("- Removing this SID from force_enable_sids would return control to the normal feed/category/semantic policy.")
    if rule.restored_dependency_types:
        lines.append("- This rule remains active while a final-enabled consumer requires the state it sets; dependency restoration is calculated dynamically.")
    if rule.final_enabled and base_enabled and not semantic_names and not tracked and not rule.restored_dependency_types:
        lines.append("- The rule is active because its category policy preserves/enables the feed state; changing that category policy or the feed state changes the result.")

    lines.extend(["", "RULE METADATA"])
    lines.append(f"classtype: {classtype_m.group(1).strip() if classtype_m else '-'}")
    if rule.metadata:
        for key in sorted(rule.metadata):
            lines.append(f"metadata.{key}: {', '.join(rule.metadata[key])}")
    else:
        lines.append("metadata: -")
    lines.append(f"references: {', '.join(refs) if refs else '-'}")

    lines.extend([
        "",
        "SUMMARY",
        f"This SID is {'ENABLED' if rule.final_enabled else 'DISABLED'} after tuning.",
    ])
    if sid in result.get("semantic_keep", set()):
        lines.append("A semantic selector contributed to keeping this rule.")
    if sid in result.get("tracked_keep", set()):
        lines.append("The SID is tracked for drift across feed updates.")
    if rule.restored_dependency_types:
        lines.append("The final state also depends on dynamic dependency restoration.")
    lines.extend(["", "RAW RULE", rule.raw])
    return lines


def print_sid_explanation(args, sid: int) -> int:
    print("\n".join(build_sid_explanation(args, sid)))
    return 0


def collect_sid_audit(args, status_cb=None):
    """Collect one tracked-SID audit, optionally reporting coarse progress stages.

    This is intentionally deterministic and side-effect free. The progress callback
    is used by the TUI so large rulesets never look like a frozen application.
    """
    import tune_rules as tuner

    def status(message: str):
        if status_cb:
            status_cb(message)

    status("Loading policy")
    policy = tuner.core.load_policy(args.policy)
    baseline = resolve_baseline(policy, args.policy)

    status("Reading and parsing current ruleset")
    rules = tuner.core.load_rules(args.rules)

    total = len(rules)
    step = max(1000, total // 20 if total else 1000)
    status(f"Normalizing logical categories — 0/{total:,}")
    for idx, rule in enumerate(rules.values(), 1):
        rule.category = tuner.core.map_category(rule.msg, policy)
        if idx == total or idx % step == 0:
            status(f"Normalizing logical categories — {idx:,}/{total:,}")

    tracked_count = len(tuner.tracked_sid_set(policy))
    status(f"Comparing {tracked_count:,} tracked SID fingerprints")
    audit = tuner.audit_tracked_rules(rules, policy, baseline)
    status("Preparing SID integrity results")
    return policy, rules, baseline, audit


def _sid_check_progress(stdscr, args):
    """Run the SID audit in a worker so curses remains visibly responsive."""
    state = {
        "stage": "Starting SID integrity check",
        "done": False,
        "result": None,
        "error": None,
    }
    lock = threading.Lock()

    def set_stage(message: str):
        with lock:
            state["stage"] = message

    def worker():
        try:
            result = collect_sid_audit(args, set_stage)
            with lock:
                state["result"] = result
        except Exception as exc:
            with lock:
                state["error"] = exc
        finally:
            with lock:
                state["done"] = True

    thread = threading.Thread(target=worker, name="sid-audit", daemon=True)
    thread.start()
    spinner = "|/-\\"
    spinner_idx = 0
    started = time.monotonic()

    if hasattr(stdscr, "nodelay"):
        stdscr.nodelay(True)
    try:
        while True:
            with lock:
                done = bool(state["done"])
                stage = str(state["stage"])
                error = state["error"]
                result = state["result"]
            if done:
                if error is not None:
                    raise error
                return result

            draw_header(
                stdscr,
                "Check SIDs",
                "SID integrity scan is running.",
                "Large rule feeds can take a while to parse. No files are being modified.",
            )
            elapsed = int(time.monotonic() - started)
            safe_addstr(
                stdscr,
                5,
                3,
                f"{spinner[spinner_idx % len(spinner)]}  {stage}",
                color(1) | curses.A_BOLD,
            )
            safe_addstr(stdscr, 7, 3, f"Elapsed: {elapsed}s", curses.A_DIM)
            safe_addstr(stdscr, 9, 3, "Working... results will appear automatically when the scan completes.")
            stdscr.refresh()
            spinner_idx += 1
            # Read and discard keys while running so terminal input does not build up.
            try:
                stdscr.getch()
            except Exception:
                pass
            curses.napms(100)
    finally:
        if hasattr(stdscr, "nodelay"):
            stdscr.nodelay(False)


def _sid_explain_progress(stdscr, args, sid: int):
    """Build Explain SID text without making the TUI appear frozen."""
    state = {"done": False, "result": None, "error": None}
    lock = threading.Lock()

    def worker():
        try:
            result = build_sid_explanation(args, sid)
            with lock:
                state["result"] = result
        except Exception as exc:
            with lock:
                state["error"] = exc
        finally:
            with lock:
                state["done"] = True

    thread = threading.Thread(target=worker, name=f"sid-explain-{sid}", daemon=True)
    thread.start()
    spinner = "|/-\\"
    spinner_idx = 0
    started = time.monotonic()
    if hasattr(stdscr, "nodelay"):
        stdscr.nodelay(True)
    try:
        while True:
            with lock:
                done = bool(state["done"])
                result = state["result"]
                error = state["error"]
            if done:
                if error is not None:
                    raise error
                return result
            draw_header(
                stdscr,
                f"Explain SID {sid}",
                "Evaluating this SID through the current policy engine.",
                "No policy or rule files are being changed.",
            )
            safe_addstr(stdscr, 5, 3, f"{spinner[spinner_idx % len(spinner)]}  Building decision trace", color(1) | curses.A_BOLD)
            safe_addstr(stdscr, 7, 3, f"Elapsed: {int(time.monotonic() - started)}s", curses.A_DIM)
            stdscr.refresh()
            spinner_idx += 1
            try:
                stdscr.getch()
            except Exception:
                pass
            curses.napms(100)
    finally:
        if hasattr(stdscr, "nodelay"):
            stdscr.nodelay(False)


def prompt_sid_to_explain(stdscr) -> Optional[str]:
    """Prompt for a Suricata signature ID with enough context for first-time users."""
    while True:
        draw_header(
            stdscr,
            "Explain SID",
            "Enter the numeric SID (signature ID) of the Suricata rule you want explained.",
            "Enter: Explain   Esc/q: Back",
        )
        safe_addstr(stdscr, 4, 3, "A SID is the rule's numeric identifier.", curses.A_BOLD)
        safe_addstr(stdscr, 5, 3, "Example: 2001294", curses.A_DIM)
        safe_addstr(stdscr, 7, 3, "The explanation shows why the rule is enabled/disabled, which policy", 0)
        safe_addstr(stdscr, 8, 3, "decision matched it, and any flowbit/xbit or tracked-SID dependencies.", 0)
        safe_addstr(stdscr, 10, 3, "SID: ", color(1) | curses.A_BOLD)
        stdscr.refresh()
        curses.echo()
        curses.curs_set(1)
        try:
            stdscr.move(10, 8)
            raw = stdscr.getstr(10, 8, 24)
            value = raw.decode("utf-8", errors="replace").strip()
        finally:
            curses.noecho()
            curses.curs_set(0)
        if value == "\x1b" or value.lower() in {"q", "quit", "back"}:
            return None
        if value == "":
            return None
        if value.isdigit():
            return value
        safe_addstr(stdscr, 12, 3, "Please enter digits only, for example 2001294.", color(4) | curses.A_BOLD)
        stdscr.refresh()
        curses.napms(1200)


def check_sids_screen(stdscr,args):
    try:
        import tune_rules as tuner
    except Exception as exc:
        draw_header(stdscr,"Check SIDs"); safe_addstr(stdscr,4,2,f"Cannot import tuner core: {exc}",color(4)); pause_screen(stdscr); return

    # Scan once on entry. Help/Explain navigation reuses this result; a full
    # rescan happens only when the operator explicitly presses r or accepts a
    # new baseline.
    try:
        current = _sid_check_progress(stdscr, args)
    except Exception as exc:
        draw_header(stdscr,"Check SIDs"); safe_addstr(stdscr,4,2,f"SID check failed: {exc}",color(4)); pause_screen(stdscr); return

    while True:
        policy, rules, baseline, audit = current
        draw_header(stdscr,"Check SIDs","Current feed vs tracked SID fingerprint baseline",
                    "q: Back   r: Recheck   e: Explain SID   ?: Help   a: Accept baseline")
        y=4
        rows=[
            ("Tracked",audit.get("tracked",0)), ("OK / unchanged", len(audit.get("ok",[]) or [])),
            ("No baseline entry", len(audit.get("unbaselined",[]) or [])),
            ("Revision changed",len(audit.get("rev_changed",[]) or [])),("Logic changed",len(audit.get("logic_changed",[]) or [])),
            ("Message changed",len(audit.get("message_changed",[]) or [])),("Category changed",len(audit.get("category_changed",[]) or [])),
            ("Missing",len(audit.get("missing",[]) or [])),("Feed disabled",len(audit.get("feed_disabled",[]) or [])),
        ]
        for label,val in rows:
            issue=label not in {"Tracked","OK / unchanged"} and bool(val)
            safe_addstr(stdscr,y,3,f"{label:<20}: {val}",color(3) if issue else 0); y+=1
        y+=1
        safe_addstr(stdscr,y,3,f"Baseline: {baseline}",curses.A_DIM); y+=2
        issue_keys=("unbaselined","logic_changed","rev_changed","message_changed","category_changed","missing","feed_disabled")
        shown=0
        for key in issue_keys:
            vals=audit.get(key,[]) or []
            if vals and shown<8:
                safe_addstr(stdscr,y,3,f"{key}: {', '.join(str(x) for x in vals[:12])}",color(3)); y+=1; shown+=1
        if audit.get("baseline_missing"):
            safe_addstr(stdscr,y,3,"Baseline is missing. Review the feed, then press 'a' to create it.",color(3)); y+=1
        stdscr.refresh(); ch=stdscr.getch()
        if ch in (ord('q'),27): return
        if ch==ord('r'):
            try:
                current = _sid_check_progress(stdscr, args)
            except Exception as exc:
                draw_header(stdscr,"Check SIDs"); safe_addstr(stdscr,4,2,f"SID check failed: {exc}",color(4)); pause_screen(stdscr); return
            continue
        if ch==ord('e'):
            raw_sid=prompt_sid_to_explain(stdscr)
            if raw_sid:
                try:
                    sid=int(raw_sid)
                    explanation = _sid_explain_progress(stdscr, args, sid)
                    text_viewer(stdscr,f"Explain SID {sid}",explanation,
                                "Exact policy-engine reasoning for the current ruleset")
                except ValueError:
                    safe_addstr(stdscr,y+1,3,"SID must be an integer.",color(4)); stdscr.refresh(); curses.napms(1000)
                except Exception as exc:
                    safe_addstr(stdscr,y+1,3,f"Explain failed: {exc}",color(4)); stdscr.refresh(); curses.napms(1400)
            continue
        if ch==ord('?'):
            text_viewer(stdscr,"Check SIDs / Help",[
                "Tracked SID checks compare selected high-value SIDs with a saved fingerprint baseline.",
                "",
                "The scan screen shows a live spinner, elapsed time and the current stage. Large rule feeds can take a while to parse; the visible progress means the application is still working.",
                "The parsed result is kept in memory while you remain in Check SIDs. Opening Help or Explain does not automatically rescan the entire feed. Press r only when you want a fresh scan.",
                "",
                "OK / unchanged: the SID exists in the feed, has a baseline entry, and its tracked fingerprint fields did not change.",
                "No baseline entry: the SID is tracked by policy but this baseline has no stored fingerprint for it yet.",
                "Revision changed: the rule writer incremented rev. Review it; a REV change may be benign or may accompany logic changes.",
                "Logic changed: the packet/detection logic fingerprint changed after descriptive fields such as metadata, reference, classtype and rev are normalized out.",
                "Message changed: the human-readable msg changed.",
                "Category changed: the rule now maps to a different logical policy category.",
                "Missing: the exact SID no longer exists in the current feed.",
                "Feed disabled: the vendor/feed currently ships the tracked SID disabled; the tuner does not silently force it on unless force_enable_sids explicitly says so.",
                "",
                "Press e and enter any SID to see Explain Mode: current feed state, final tuner state, category/mode/strategy, semantic and tracked overrides, asset evidence, flowbits/xbits, baseline drift, metadata and the raw rule.",
                "",
                "Only accept a new baseline after reviewing meaningful changes.",
            ],"Meaning of SID integrity statuses")
            continue
        if ch==ord('a') and confirm(stdscr,"Accept CURRENT tracked SID fingerprints as the new baseline?"):
            try:
                baseline.parent.mkdir(parents=True,exist_ok=True)
                if baseline.exists(): shutil.copy2(baseline,baseline.with_suffix(baseline.suffix+".bak"))
                baseline.write_text(json.dumps(tuner.build_tracked_baseline(rules,policy),indent=2)+"\n",encoding="utf-8")
                safe_addstr(stdscr,y+1,3,"Baseline accepted. Rechecking...",color(2)); stdscr.refresh(); curses.napms(500)
                current = _sid_check_progress(stdscr, args)
            except Exception as exc:
                safe_addstr(stdscr,y+1,3,f"Failed: {exc}",color(4)); stdscr.refresh(); curses.napms(1400)



def environment_check(args)->int:
    print("Suricata Policy Engine TUI - environment check")
    print(f"Python           : {sys.version.split()[0]}")
    print(f"PyYAML           : {'OK' if yaml is not None else 'MISSING'}")
    print("curses           : OK")
    print(f"Policy           : {'OK' if args.policy.exists() else 'MISSING'}  {args.policy}")
    print(f"Rules            : {'OK' if args.rules.exists() else 'MISSING'}  {args.rules}")
    print(f"Suricata config  : {'OK' if args.suricata_conf.exists() else 'MISSING'}  {args.suricata_conf}")
    for exe in ("suricata-update","suricata","suricatasc"):
        print(f"{exe:<17}: {shutil.which(exe) or 'not found'}")
    if shutil.which("suricata"):
        try:
            ver=subprocess.run([shutil.which("suricata"),"-V"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=3).stdout.strip()
            print(f"Suricata version : {ver}")
        except Exception:
            pass
    try:
        import run_history
        print(f"History runs     : {len(run_history.list_runs(run_history.default_history_dir(args.output)))}")
    except Exception:
        pass
    try:
        if args.policy.exists():
            p=load_policy(args.policy); print(f"Policy parse     : OK ({len(p.get('categories',{}))} categories)")
    except Exception as exc:
        print(f"Policy parse     : FAILED: {exc}"); return 2
    return 0 if yaml is not None and args.policy.exists() else 1


def _run_screen_safely(stdscr, title: str, func, *args) -> None:
    """Keep a single editor bug from terminating the entire curses application."""
    try:
        func(stdscr, *args)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        text_viewer(
            stdscr,
            f"{title} / Error",
            [
                "This screen hit an unexpected error, but the TUI is still running.",
                "",
                f"{type(exc).__name__}: {exc}",
                "",
                "No policy change was saved by this failed screen action.",
            ],
            "Return to the menu; the rest of the application remains available.",
        )


def main_tui(stdscr,args):
    curses.curs_set(0); stdscr.keypad(True); init_colors()
    # Four focused main actions. q exits from the main menu.
    items=[
        ("Dashboard","Current effective policy and operational status"),
        ("Policy Editor","Standard Settings for daily use + full Advanced Settings"),
        ("Tune My Rules","Review effective policy, confirm, then tune with validation and optional activation"),
        ("Check SIDs","Audit tracked SID drift and explain any SID decision"),
    ]
    sel=0
    while True:
        draw_header(stdscr,"Main Menu",f"User: {'root' if os.geteuid()==0 else os.geteuid()}   Active: {_active_policy_label(args.policy)}","q: Exit   ↑↓: Navigate   Enter: Select")
        for i,(name,desc) in enumerate(items):
            attr=curses.A_REVERSE if i==sel else 0
            safe_addstr(stdscr,4+i*3,3,f"{name:<20}",attr|curses.A_BOLD); safe_addstr(stdscr,5+i*3,6,desc,attr)
        stdscr.refresh(); ch=stdscr.getch()
        if ch in (ord('q'),27): return
        if ch in (curses.KEY_UP,ord('k')): sel=(sel-1)%len(items)
        elif ch in (curses.KEY_DOWN,ord('j')): sel=(sel+1)%len(items)
        elif ch in (10,13,ord(' ')):
            if sel==0: _run_screen_safely(stdscr, "Dashboard", show_dashboard, args)
            elif sel==1: _run_screen_safely(stdscr, "Policy Editor", policy_editor, args)
            elif sel==2: _run_screen_safely(stdscr, "Tune My Rules", tune_rules_action, args)
            elif sel==3: _run_screen_safely(stdscr, "Check SIDs", check_sids_screen, args)


def main()->int:
    args=parse_args()
    if args.check: return environment_check(args)
    if args.explain_sid is not None: return print_sid_explanation(args,args.explain_sid)
    try: curses.wrapper(main_tui,args)
    except KeyboardInterrupt: return 130
    except curses.error as exc:
        print(f"TUI error: {exc}\nTry a larger terminal or run: python3 tui.py --check",file=sys.stderr); return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
