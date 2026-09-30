#!/usr/bin/env python3
import copy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import generate_suricata_policy as core
import tune_rules
import policy_insights as insights


class V10InsightsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_policy=core.load_policy(ROOT/'tuning-policy.yaml')

    def make_rule(self,sid,msg,enabled=True,rev=1):
        raw=f'alert tcp any any -> any any (msg:"{msg}"; sid:{sid}; rev:{rev};)'
        return core.Rule(sid=sid,rev=rev,msg=msg,raw=raw,source_enabled=enabled,metadata={})

    def test_recommends_prohibited_detection_contradiction(self):
        policy=copy.deepcopy(self.base_policy)
        policy['organization_policy']['tor']['prohibited']=True
        policy['organization_policy']['tor']['detection_enabled']=False
        r=self.make_rule(1,'ET TOR Known TOR Relay')
        rules={1:r}
        result=tune_rules.apply_policy(rules,policy)
        audit={'tracked':0,'ok':[],'missing':[],'feed_disabled':[],'rev_changed':[],'logic_changed':[],'message_changed':[],'category_changed':[],'baseline_missing':False}
        recs=insights.generate_recommendations(rules,policy,result,audit,None)
        codes={x['code'] for x in recs}
        self.assertIn('org-tor-prohibited-undetected',codes)

    def test_health_is_not_security_score_and_deducts_findings(self):
        policy=copy.deepcopy(self.base_policy)
        r=self.make_rule(2,'ET MALWARE Test')
        rules={2:r}
        result=tune_rules.apply_policy(rules,policy)
        audit={'tracked':0,'ok':[],'missing':[],'feed_disabled':[],'rev_changed':[],'logic_changed':[],'message_changed':[],'category_changed':[],'baseline_missing':False}
        rec=[{'severity':'high','code':'x','title':'x','why':'x','action':'x','evidence':{}}]
        health=insights.policy_health_report(policy,rules,result,audit,rec)
        self.assertEqual(health['score'],90)
        self.assertIn('not a security coverage',health['note'].lower())

    def test_update_impact_counts_active_new_rules(self):
        r1=self.make_rule(10,'ET MALWARE New Rule',True,1); r1.category='ET_MALWARE'; r1.final_enabled=True
        r2=self.make_rule(11,'ET INFO New Rule',True,1); r2.category='ET_INFO'; r2.final_enabled=False
        rules={10:r1,11:r2}
        diff={'baseline':False,'new_sids':[10,11],'removed_sids':[9],'rev_changed':[10],'newly_enabled':[10],'newly_disabled':[]}
        prev={'rules':{'9':{'enabled':True}}}
        impact=insights.build_update_impact(diff,rules,prev,{})
        self.assertEqual(impact['new_sids'],2)
        self.assertEqual(impact['new_final_enabled'],1)
        self.assertEqual(impact['removed_were_enabled'],1)
        self.assertEqual(impact['categories']['ET_MALWARE']['new'],1)

    def test_ambiguous_asset_candidate_becomes_recommendation(self):
        policy=copy.deepcopy(self.base_policy)
        r=self.make_rule(20,'ET WEB_SPECIFIC_APPS NGINX Something')
        r.category='ET_WEB_SPECIFIC_APPS'; r.asset_review_candidate=True; r.asset_match_asset='nginx'; r.asset_match_score=60
        rules={20:r}
        result={'missing_flow':set(),'missing_xbit':set(),'unknown_enabled':0,'unresolved_selective':{}}
        audit={'baseline_missing':False,'missing':[],'logic_changed':[],'category_changed':[],'rev_changed':[],'message_changed':[],'feed_disabled':[]}
        recs=insights.generate_recommendations(rules,policy,result,audit,None)
        self.assertIn('ambiguous-asset-matches',{x['code'] for x in recs})

if __name__=='__main__': unittest.main(verbosity=2)
