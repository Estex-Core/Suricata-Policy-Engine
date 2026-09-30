#!/usr/bin/env python3
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import tui

class ExplainSidTests(unittest.TestCase):
    def test_explain_sid_reports_policy_decision(self):
        with tempfile.TemporaryDirectory() as td:
            rules=Path(td)/'suricata.rules'
            rules.write_text('alert tcp any any -> any any (msg:"ET MALWARE Explain Test"; content:"abc"; classtype:trojan-activity; sid:9990001; rev:3;)\n',encoding='utf-8')
            args=Namespace(policy=ROOT/'tuning-policy.yaml',rules=rules,output=Path(td)/'out.rules',suricata_conf=Path(td)/'suricata.yaml')
            text='\n'.join(tui.build_sid_explanation(args,9990001))
            self.assertIn('Final tuner state: ACTIVE',text)
            self.assertIn('Logical category: ET_MALWARE',text)
            self.assertIn('Mode: preserve_feed',text)
            self.assertIn('Reason code: preserve_feed_state',text)

    def test_explain_missing_sid_is_clear(self):
        with tempfile.TemporaryDirectory() as td:
            rules=Path(td)/'suricata.rules'
            rules.write_text('alert tcp any any -> any any (msg:"ET MALWARE Other"; sid:9990002; rev:1;)\n',encoding='utf-8')
            args=Namespace(policy=ROOT/'tuning-policy.yaml',rules=rules,output=Path(td)/'out.rules',suricata_conf=Path(td)/'suricata.yaml')
            text='\n'.join(tui.build_sid_explanation(args,123456789))
            self.assertIn('Current feed state: MISSING',text)

    def test_log_view_retains_full_buffer_and_clamps(self):
        self.assertEqual(tui._log_view_top(100, 20, 0, True), 80)
        self.assertEqual(tui._log_view_top(100, 20, 30, False), 30)
        self.assertEqual(tui._log_view_top(5, 20, 99, False), 0)

    def test_activation_prompt_has_safe_default(self):
        class FakeScreen:
            def getmaxyx(self): return (30, 120)
            def refresh(self): pass
            def getch(self): return 10
        old_draw, old_add, old_color = tui.draw_header, tui.safe_addstr, tui.color
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            self.assertFalse(tui.confirm_activation(FakeScreen(), Path('/feed/suricata.rules'), Path('/rules/suricata-tuned.rules')))
        finally:
            tui.draw_header, tui.safe_addstr, tui.color = old_draw, old_add, old_color

if __name__=='__main__':
    unittest.main(verbosity=2)

class TuiUxTests(unittest.TestCase):
    def test_default_policy_detects_balanced_recommended_profile(self):
        from profiles import PROFILES
        policy = tui.load_policy(ROOT / 'tuning-policy.yaml')
        self.assertTrue(PROFILES['Balanced']['recommended'])
        self.assertEqual(tui._detect_active_profile(ROOT / 'tuning-policy.yaml', policy, PROFILES), 'Balanced')

    def test_profile_state_records_exact_selection(self):
        from profiles import PROFILES
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui._record_active_profile(policy_path, 'Lab / Experimental')
            policy = tui.load_policy(policy_path)
            self.assertEqual(tui._detect_active_profile(policy_path, policy, PROFILES), 'Lab / Experimental')

    def test_tune_stage_recognizes_live_progress(self):
        self.assertEqual(tui._tune_stage('[2/5] Parsing Suricata rules...', 'x'), 'Parsing Suricata rules')
        self.assertEqual(tui._tune_stage('[TEST] Running Suricata configuration/rule test...', 'x'), 'Validating with suricata -T')

    def test_live_runner_starts_and_completes_without_intermediate_keypress(self):
        class FakeScreen:
            def getmaxyx(self): return (24, 100)
            def refresh(self): pass
            def getch(self): return 10
            def nodelay(self, _flag): pass
        old_draw, old_add, old_color = tui.draw_header, tui.safe_addstr, tui.color
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            rc, lines = tui.run_with_progress(
                FakeScreen(),
                [sys.executable, '-c', '[(print(f"line-{i}", flush=True)) for i in range(20)]; print("[TEST] PASS", flush=True)'],
                'test',
            )
            self.assertEqual(rc, 0)
            self.assertEqual(len(lines), 21)
            self.assertEqual(lines[0], 'line-0')
            self.assertTrue(any('[TEST] PASS' in line for line in lines))
        finally:
            tui.draw_header, tui.safe_addstr, tui.color = old_draw, old_add, old_color

class EffectivePolicyStateTests(unittest.TestCase):
    def test_manual_edit_marks_policy_custom_based_on_profile(self):
        from profiles import PROFILES
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui._record_active_profile(policy_path, 'Balanced')
            tui.apply_policy_changes(policy_path, {('assets','web_specific_apps','wordpress','enabled'): True})
            state = tui._policy_state(policy_path, tui.load_policy(policy_path), PROFILES)
            self.assertTrue(state['custom'])
            self.assertEqual(state['base_profile'], 'Balanced')
            self.assertEqual(state['label'], 'Custom (based on Balanced Recommended)')
            self.assertIsNone(tui._detect_active_profile(policy_path, tui.load_policy(policy_path), PROFILES))


    def test_low_noise_advanced_edit_is_visibly_custom(self):
        from profiles import PROFILES
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui.apply_policy_changes(policy_path, PROFILES['Strict']['changes'], source='profile')
            tui._record_active_profile(policy_path, 'Strict')
            tui.apply_policy_changes(policy_path, {('categories','ET_INFO','mode'): 'preserve_feed'})
            state = tui._policy_state(policy_path, tui.load_policy(policy_path), PROFILES)
            self.assertTrue(state['custom'])
            self.assertEqual(state['label'], 'Custom (based on Strict)')
            self.assertEqual(tui._profile_display_marker('Strict', state), '↳ ')
            self.assertNotEqual(tui._profile_display_marker('Strict', state), '▶ ')

    def test_active_profile_uses_active_marker(self):
        state = {'base_profile': 'Strict', 'custom': False, 'label': 'Strict'}
        self.assertEqual(tui._profile_display_marker('Strict', state), '▶ ')
    def test_profile_apply_resets_custom_state(self):
        from profiles import PROFILES
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui._record_active_profile(policy_path, 'Balanced')
            tui.apply_policy_changes(policy_path, {('assets','web_specific_apps','wordpress','enabled'): True})
            self.assertTrue(tui._policy_state(policy_path, tui.load_policy(policy_path), PROFILES)['custom'])
            tui.apply_policy_changes(policy_path, PROFILES['Strict']['changes'], source='profile')
            tui._record_active_profile(policy_path, 'Strict')
            state = tui._policy_state(policy_path, tui.load_policy(policy_path), PROFILES)
            self.assertFalse(state['custom'])
            self.assertEqual(state['label'], 'Strict')


class EffectivePolicySummaryTests(unittest.TestCase):
    def test_summary_describes_exact_effective_policy(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui._record_active_profile(policy_path, 'Balanced')
            lines = tui.effective_policy_summary(policy_path)
            text = "\n".join(lines)
            self.assertIn('ACTIVE POLICY: Balanced (Recommended)', text)
            self.assertIn('web_server:', text)
            self.assertIn('enabled: ON', text)
            self.assertIn('nginx:', text)
            self.assertIn('dependency_restore:', text)
            self.assertIn('enabled: ON', text)

    def test_summary_reflects_custom_edit(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / 'policy.yaml'
            policy_path.write_bytes((ROOT / 'tuning-policy.yaml').read_bytes())
            tui._record_active_profile(policy_path, 'Balanced')
            tui.apply_policy_changes(policy_path, {('assets','web_specific_apps','wordpress','enabled'): True})
            text = "\n".join(tui.effective_policy_summary(policy_path))
            self.assertIn('ACTIVE POLICY: Custom (based on Balanced Recommended)', text)
            self.assertIn('wordpress:', text)

class PreTuneConfirmationTests(unittest.TestCase):
    def _run_confirm(self, key):
        class FakeScreen:
            def getmaxyx(self): return (40, 120)
            def refresh(self): pass
            def getch(self): return key
        old_draw, old_add, old_color = tui.draw_header, tui.safe_addstr, tui.color
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            return tui.confirm_tune_policy(FakeScreen(), ROOT / 'tuning-policy.yaml')
        finally:
            tui.draw_header, tui.safe_addstr, tui.color = old_draw, old_add, old_color

    def test_pre_tune_confirmation_requires_explicit_t(self):
        self.assertTrue(self._run_confirm(ord('t')))
        self.assertTrue(self._run_confirm(ord('T')))

    def test_pre_tune_confirmation_enter_starts_tuning(self):
        self.assertTrue(self._run_confirm(10))
        self.assertFalse(self._run_confirm(ord('q')))

    def test_tune_action_does_not_start_when_policy_review_is_cancelled(self):
        calls = []
        old_confirm, old_run = tui.confirm_tune_policy, tui.run_with_progress
        try:
            tui.confirm_tune_policy = lambda *_a, **_k: False
            tui.run_with_progress = lambda *_a, **_k: calls.append(True) or (0, [])
            args = Namespace(
                policy=ROOT/'tuning-policy.yaml',
                rules=Path('/tmp/suricata.rules'),
                output=Path('/tmp/suricata-tuned.rules'),
                suricata_conf=Path('/tmp/suricata.yaml'),
            )
            tui.tune_rules_action(object(), args)
            self.assertEqual(calls, [])
        finally:
            tui.confirm_tune_policy, tui.run_with_progress = old_confirm, old_run

class CompactPolicyUiTests(unittest.TestCase):
    def test_asset_overview_has_one_row_per_asset(self):
        policy = tui.load_policy(ROOT / 'tuning-policy.yaml')
        rows = tui._asset_overview_rows(policy)
        labels = [row[1] for row in rows]
        self.assertEqual(labels.count('Nginx'), 1)
        self.assertEqual(dict((row[1], row[2]) for row in rows)['Nginx'], 'ON')
        self.assertIn('WordPress', labels)
        # Matcher internals must not be separate overview rows.
        self.assertFalse(any('threshold' in label.lower() or 'regex' in label.lower() or 'alias' in label.lower() for label in labels))

    def test_organization_summary_collapses_usage_and_detection(self):
        self.assertEqual(tui._organization_policy_summary(True, True), 'Prohibited + Detect')
        self.assertEqual(tui._organization_policy_summary(False, True), 'Allowed + Detect')
        self.assertEqual(tui._organization_policy_summary(False, False), 'Allowed + No detection')
        self.assertEqual(tui._organization_policy_summary(None, False), 'No usage decision + No detection')
        self.assertNotIn('NOT SET', tui._organization_policy_summary(None, False))

    def test_remote_access_summary_is_single_human_status(self):
        self.assertEqual(
            tui._remote_access_summary({'default_policy':'prohibited','detection_enabled':True}),
            'Prohibited by default + Detect'
        )


class PostTuneChoiceTests(unittest.TestCase):
    def _choice(self, key):
        class FakeScreen:
            def getmaxyx(self): return (40, 140)
            def refresh(self): pass
            def getch(self): return key
        old_draw, old_add, old_color = tui.draw_header, tui.safe_addstr, tui.color
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            return tui.production_choice(FakeScreen(), Path('/feed/suricata.rules'), Path('/rules/suricata-tuned.rules'))
        finally:
            tui.draw_header, tui.safe_addstr, tui.color = old_draw, old_add, old_color

    def test_keep_is_safe_default(self):
        self.assertEqual(self._choice(10), 'keep')

    def test_activate_and_replace_are_explicit(self):
        self.assertEqual(self._choice(ord('a')), 'activate')
        self.assertEqual(self._choice(ord('r')), 'replace')


class CompleteEffectiveSummaryTests(unittest.TestCase):
    def test_summary_covers_all_execution_sections_and_entries(self):
        policy = tui.load_policy(ROOT / 'tuning-policy.yaml')
        text = "\n".join(tui.effective_policy_summary(ROOT / 'tuning-policy.yaml'))
        for section in (
            'CATEGORY POLICY', 'ASSETS / TECHNOLOGIES', 'ORGANIZATION POLICY',
            'DEFAULTS & DEPENDENCIES', 'RULE OVERRIDES',
            'SEMANTIC / SELECTIVE CATEGORY LOGIC', 'ALERT TUNING',
            'TELEMETRY', 'VALIDATION', 'ADVANCED GPL MAPPINGS'
        ):
            self.assertIn(section, text)
        for category in policy.get('categories', {}):
            self.assertIn(f'{category}:', text)
        for asset in (policy.get('assets', {}).get('web_specific_apps', {}) or {}):
            self.assertIn(f'{asset}:', text)
        for key in policy.get('validation', {}):
            self.assertIn(f'{key}:', text)
        for sid_category in policy.get('rule_overrides', {}):
            self.assertIn(f'{sid_category}:', text)
        self.assertNotIn('audit_date:', text)

class CompactUxRegressionTests(unittest.TestCase):
    def test_concise_tune_summary_is_short_and_decision_focused(self):
        lines = tui.concise_tune_summary(ROOT / 'tuning-policy.yaml')
        text = '\n'.join(lines)
        self.assertLessEqual(len(lines), 24)
        self.assertIn('CATEGORY POLICY', text)
        self.assertIn('ORGANIZATION POLICY', text)
        self.assertIn('TUNING SAFETY', text)
        self.assertNotIn('ADVANCED GPL MAPPINGS', text)

    def test_live_runner_does_not_force_completed_log_viewer(self):
        class FakeScreen:
            def getmaxyx(self): return (24, 100)
            def refresh(self): pass
            def getch(self): return -1
            def nodelay(self, _flag): pass
        old_draw, old_add, old_color, old_view = tui.draw_header, tui.safe_addstr, tui.color, tui._completed_log_viewer
        called = []
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            tui._completed_log_viewer = lambda *a, **k: called.append(True)
            rc, lines = tui.run_with_progress(FakeScreen(), [sys.executable, '-c', 'print("[TEST] PASS", flush=True)'], 'test')
            self.assertEqual(rc, 0)
            self.assertTrue(lines)
            self.assertEqual(called, [])
        finally:
            tui.draw_header, tui.safe_addstr, tui.color, tui._completed_log_viewer = old_draw, old_add, old_color, old_view

    def test_result_screen_keeps_safe_default(self):
        class FakeScreen:
            def getmaxyx(self): return (30, 120)
            def refresh(self): pass
            def getch(self): return 10
        old_draw, old_add, old_color = tui.draw_header, tui.safe_addstr, tui.color
        try:
            tui.draw_header = lambda *a, **k: None
            tui.safe_addstr = lambda *a, **k: None
            tui.color = lambda *a, **k: 0
            choice = tui.production_choice(FakeScreen(), Path('/feed/suricata.rules'), Path('/rules/suricata-tuned.rules'), {'source_enabled_rules': 100, 'final_enabled_rules': 70}, ['line'])
            self.assertEqual(choice, 'keep')
        finally:
            tui.draw_header, tui.safe_addstr, tui.color = old_draw, old_add, old_color


class DashboardSummaryRegressionTests(unittest.TestCase):
    def test_compact_policy_summary_exists_and_is_small(self):
        lines = tui.compact_policy_summary(ROOT / 'tuning-policy.yaml')
        text = '\n'.join(lines)
        self.assertLessEqual(len(lines), 6)
        self.assertIn('Active Policy', text)
        self.assertIn('Assets', text)
        self.assertIn('Org policy', text)
        self.assertIn('Safety', text)

    def test_dashboard_reminder_wording_is_clear(self):
        source = (ROOT / 'src' / 'tui.py').read_text()
        self.assertIn('A DISABLED RULE IS NOT NECESSARILY USELESS', source)
        self.assertNotIn('REMEMBER OFF DOES NOT MEAN USELESS', source)

    def test_advanced_assets_about_is_actionable(self):
        source = (ROOT / 'src' / 'tui.py').read_text()
        self.assertIn('What technologies do you actually have in the environment Suricata monitors?', source)
        self.assertIn('Turn them ON here.', source)
