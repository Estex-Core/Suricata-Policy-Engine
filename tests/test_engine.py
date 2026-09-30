#!/usr/bin/env python3
import sys, unittest, yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import generate_suricata_policy as core

class V6EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy=core.load_policy(ROOT/'tuning-policy.yaml')

    def rule(self,sid,msg,metadata=''):
        raw=f'alert http any any -> any any (msg:"{msg}"; sid:{sid}; rev:1; '
        if metadata: raw+=f'metadata:{metadata}; '
        raw+=')'
        r=core.Rule(sid=sid,rev=1,msg=msg,raw=raw,source_enabled=True,metadata=core.parse_metadata(raw))
        return r

    def test_nginx_anchored_match(self):
        r=self.rule(1,'ET WEB_SPECIFIC_APPS NGINX UI Authenticated RCE');r.category='ET_WEB_SPECIFIC_APPS'
        enabled,_=core.web_specific_app_decision(r,self.policy)
        self.assertTrue(enabled); self.assertEqual(r.asset_match_asset,'nginx')

    def test_nginx_metadata_match(self):
        r=self.rule(2,'ET WEB_SPECIFIC_APPS Product Label','affected_product Nginx, attack_target Server');r.category='ET_WEB_SPECIFIC_APPS'
        enabled,_=core.web_specific_app_decision(r,self.policy)
        self.assertTrue(enabled); self.assertEqual(r.asset_match_score,100)

    def test_nginx_not_fuzzy_contains(self):
        r=self.rule(3,'ET WEB_SPECIFIC_APPS Discourse Nginx Configuration Issue');r.category='ET_WEB_SPECIFIC_APPS'
        enabled,_=core.web_specific_app_decision(r,self.policy)
        self.assertFalse(enabled)

    def test_semantic_keep_survives_sid_change(self):
        r=self.rule(2999999,'ET INFO Powershell Activity Over SMB - Likely Lateral Movement');r.category='ET_INFO'
        rules={r.sid:r}
        out=core.apply_explicit_overrides(rules,self.policy)
        self.assertIn(r.sid,out['semantic_keep_sids']); self.assertTrue(r.initial_enabled)

    def test_logic_hash_ignores_descriptive_churn(self):
        r1='alert tcp any any -> any any (msg:"ET MALWARE Test"; content:"abc"; reference:url,old; classtype:trojan-activity; sid:1; rev:1; metadata:foo bar;)'
        r2='alert tcp any any -> any any (msg:"ET MALWARE Test"; content:"abc"; reference:url,new; classtype:attempted-admin; sid:1; rev:9; metadata:foo baz;)'
        self.assertEqual(core.rule_logic_sha256(r1),core.rule_logic_sha256(r2))

    def test_logic_hash_detects_detection_change(self):
        r1='alert tcp any any -> any any (msg:"ET MALWARE Test"; content:"abc"; sid:1; rev:1;)'
        r2='alert tcp any any -> any any (msg:"ET MALWARE Test"; content:"xyz"; sid:1; rev:2;)'
        self.assertNotEqual(core.rule_logic_sha256(r1),core.rule_logic_sha256(r2))

if __name__=='__main__': unittest.main(verbosity=2)
