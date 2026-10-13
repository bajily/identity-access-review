import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

class IdentityTests(unittest.TestCase):
    def test_nested_permissions_and_grant_paths(self):
        grants = tool.expand_permissions(['finance'], {x['id']: x for x in tool.DEMO['groups']})
        self.assertEqual(grants['tenant:admin'], ['finance', 'approvers'])

    def test_clean_identity(self):
        data = copy.deepcopy(tool.DEMO)
        data['identities'][0].update(mfa=True, last_activity=NOW.isoformat())
        data['groups'][1]['permissions'] = ['tenant:read']
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_cycle_terminates(self):
        data = copy.deepcopy(tool.DEMO)
        data['groups'][1]['includes'] = ['finance']
        self.assertIn('IAM-GROUP-CYCLE', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_disabled_identity_not_flagged_for_mfa(self):
        data = copy.deepcopy(tool.DEMO)
        data['identities'][0]['enabled'] = False
        self.assertEqual([x['rule'] for x in tool.audit(data, {}, NOW)], ['IAM-DISABLED-GRANTS'])

    def test_unknown_group_and_duplicate_identity(self):
        for change in ['group', 'duplicate']:
            data = copy.deepcopy(tool.DEMO)
            if change == 'group':
                data['identities'][0]['groups'] = ['missing']
            else:
                data['identities'].append(copy.deepcopy(data['identities'][0]))
            with self.assertRaises(ValueError):
                tool.audit(data, {}, NOW)

    def test_policy_changes_dormancy_threshold(self):
        rules = {x['rule'] for x in tool.audit(copy.deepcopy(tool.DEMO), {'dormant_days': 999}, NOW)}
        self.assertNotIn('IAM-DORMANT-ACCESS', rules)


if __name__ == "__main__":
    unittest.main()
