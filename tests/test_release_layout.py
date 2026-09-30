from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TUI = ROOT / "src" / "tui.py"


def test_final_product_name_and_cli_entrypoint():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["name"] == "suricata-policy-engine"
    assert data["project"]["version"] == "2.0.0rc2"
    assert data["project"]["scripts"]["suricata-policy-engine"] == "tui:main"
    assert data["project"]["scripts"]["suricata-policy-engine-tui"] == "tui:main"
    assert "suricata-policy-engine-web" not in data["project"]["scripts"]
    assert "suricata-tuner-tui" not in data["project"]["scripts"]
    source = TUI.read_text(encoding="utf-8")
    assert "Suricata Policy Engine  |" in source
    assert "Suricata Friendly Tuner" not in source


def test_check_sids_is_exposed_in_tui():
    source = TUI.read_text(encoding="utf-8")
    start = source.index("def main_tui")
    main_block = source[start:source.index("def main()->int", start)]
    assert "Check SIDs" in main_block
    assert "check_sids_screen" in source

def test_policy_editor_visually_separates_standard_and_advanced():
    source = TUI.read_text(encoding="utf-8")
    assert '("", "DAY-TO-DAY POLICY")' in source
    assert '("", "ADVANCED / EXPERT")' in source
    assert source.index('("Standard Settings"') < source.index('("Advanced Settings"')


def test_required_docs_exist():
    for name in ("PROFILES.md", "POLICY-REFERENCE.md", "HOW-IT-WORKS.md"):
        path = ROOT / "docs" / name
        assert path.exists()
        assert path.stat().st_size > 500


def test_root_has_no_loose_runtime_python_modules():
    loose = sorted(p.name for p in ROOT.glob("*.py"))
    assert loose == []
    assert (ROOT / "src" / "tui.py").exists()
    assert (ROOT / "src" / "tune_rules.py").exists()


def test_github_repository_hygiene_files_exist():
    required = [
        ROOT / ".gitignore",
        ROOT / ".gitattributes",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "workflows" / "release.yml",
        ROOT / ".github" / "CONTRIBUTING.md",
        ROOT / ".github" / "SECURITY.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "RELEASE-NOTES-2.0.0rc1.md",
        ROOT / "docs" / "BACKEND-AUDIT-2.0.0b3.md",
        ROOT / "RELEASE-NOTES.md",
    ]
    for path in required:
        assert path.exists(), path


def test_current_docs_do_not_present_webui_as_supported_interface():
    current_docs = [ROOT / "README.md", ROOT / "docs" / "README.md"]
    for path in current_docs:
        text = path.read_text(encoding="utf-8").lower()
        assert "installed webui" not in text
        assert "portable offline webui" not in text
    assert (ROOT / "docs" / "archive" / "2.0.0b1" / "RELEASE-NOTES.md").exists()
