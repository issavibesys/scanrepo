import unittest

from scanrepo.engine import risk_from
from scanrepo.fsutil import classify_context
from scanrepo.models import Finding
from scanrepo.rules import load_rules

from .test_scan import make_repo
from scanrepo.context import ScanOptions
from scanrepo.engine import scan


def _scan_one(files):
    root = make_repo(files)
    return scan(str(root), ScanOptions(use_external=False))


class RegressionTest(unittest.TestCase):
    def test_test_dirs_with_suffix_are_test_context(self):
        self.assertEqual(classify_context("packages/bruno-tests/src/a.js"), "test")
        self.assertEqual(classify_context("my_fixtures/x.json"), "test")
        self.assertEqual(classify_context("packages/app/src/contest.js"), "production")

    def test_test_context_severity_is_capped(self):
        key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        report = _scan_one({"README.md": "x", "tests/k.py": f"K = '''{key}'''\n"})
        hits = [f for f in report.findings if f.rule_id == "secret.private-key"]
        self.assertTrue(hits)
        self.assertTrue(all(f.severity == "medium" for f in hits))

    def test_production_private_key_stays_critical(self):
        key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        report = _scan_one({"README.md": "x", "src/k.py": f"K = '''{key}'''\n"})
        hits = [f for f in report.findings if f.rule_id == "secret.private-key"]
        self.assertTrue(hits and hits[0].severity == "critical")

    def test_comments_are_not_code(self):
        report = _scan_one({"README.md": "x", "src/a.js": "// use dangerouslySetInnerHTML here\nconst x = 1;\n"})
        self.assertFalse([f for f in report.findings if f.rule_id == "code.js-innerhtml"])

    def test_secret_flag_in_code_is_not_hidden_feature(self):
        report = _scan_one({"README.md": "x", "src/a.js": "const secretFlag = true;\nif (secret flag changed) {}\n"})
        self.assertFalse([f for f in report.findings if f.rule_id == "beh.hidden-feature"])

    def test_checkforupdates_name_is_not_an_updater(self):
        report = _scan_one({"README.md": "x", "src/a.js": "const checkForUpdates = async () => {};\n"})
        self.assertFalse([f for f in report.findings if f.rule_id == "beh.updater"])

    def test_real_updater_is_detected(self):
        report = _scan_one({"README.md": "x", "src/main.js": "const { autoUpdater } = require('electron');\n"})
        self.assertTrue([f for f in report.findings if f.rule_id == "beh.updater"])

    def test_subfolder_readme_is_not_used_for_claims(self):
        report = _scan_one({"README.md": "x", ".claude/README.md": "Zero dependencies. No telemetry.\n"})
        self.assertFalse(report.claims)

    def test_many_hits_of_one_rule_do_not_saturate_score(self):
        f = [Finding("s", "r", "t", "medium", 0.5, "a.js", i, "", "production") for i in range(500)]
        score, level = risk_from(f)
        self.assertLess(score, 70)

    def test_default_rules_still_load(self):
        self.assertFalse(load_rules().errors)


if __name__ == "__main__":
    unittest.main()
