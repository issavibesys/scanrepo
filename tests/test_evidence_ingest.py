import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scanrepo.context import ScanOptions
from scanrepo.engine import scan

from .gitutil import git_init, head_of
from .test_scan import make_repo

README = "# demo\n\nNo telemetry, ever.\n"


def base(**kw):
    rec = {"schema": 1, "producer": "rea", "class": "B",
           "command": "analyze-javascript-application --json", "type": "claim",
           "claim_category": "no_telemetry", "effect": "contradicts",
           "observation": "package.json declares posthog-node", "file": None, "line": None}
    rec.update(kw)
    return rec


def run_scan(records, root=None, ev_dir=None):
    if root is None:
        root = make_repo({"README.md": README, "src/a.js": "const x = 1;\n"})
        head = git_init(root)
    else:
        head = head_of(root) if (root / ".git").exists() else None
    if head:
        records = [r if "target_commit" in r else {**r, "target_commit": head} for r in records]
    if ev_dir is None:
        ev_dir = Path(tempfile.mkdtemp(prefix="ev-"))
        (ev_dir / "rea.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return scan(str(root), ScanOptions(use_external=False, evidence_dir=str(ev_dir)))


def claim(report, cat="no_telemetry"):
    return [c for c in report.claims if c.category == cat][0]


def notes(report):
    return " | ".join(n for s in report.steps for n in s.notes)


class EvidenceContractTest(unittest.TestCase):
    def test_valid_class_b_record_contradicts_claim(self):
        c = claim(run_scan([base()]))
        self.assertEqual(c.status, "contradicted")
        self.assertEqual(c.evidence_class, "B")
        self.assertIn("rea", c.verified_by)
        self.assertIn("accepted", notes(run_scan([base()])))

    def test_runtime_command_is_rejected(self):
        r = run_scan([base(command="analyze-javascript-application --json --capture")])
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("runtime or capture action", notes(r))

    def test_command_outside_allowlist_is_rejected(self):
        r = run_scan([base(command="curl https://example.com")])
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("allowlist", notes(r))

    def test_shell_metacharacters_are_rejected(self):
        r = run_scan([base(command="analyze-javascript-application --json; rm -rf /")])
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("shell metacharacters", notes(r))

    def test_class_a_is_rejected_in_this_version(self):
        r = run_scan([base(**{"class": "A"})])
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("class A", notes(r))

    def test_class_c_cannot_contradict(self):
        r = run_scan([base(**{"class": "C", "producer": "manual", "command": ""})])
        c = claim(r)
        self.assertNotEqual(c.status, "contradicted")
        self.assertIn("cannot contradict", " ".join(c.evidence))

    def test_agent_hypothesis_never_changes_status(self):
        r = run_scan([
            base(**{"class": "D", "producer": "agent", "command": "", "type": "claim", "effect": "contradicts"}),
        ])
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertNotEqual(claim(r).evidence_class, "D")  # the claim keeps its own strongest evidence

    def test_agent_finding_is_info_and_low_confidence(self):
        r = run_scan([{"schema": 1, "producer": "agent", "class": "D", "command": "", "type": "finding",
                       "rule": "maybe-telemetry", "severity": "critical", "confidence": 0.95,
                       "title": "Possible telemetry", "observation": "guess from naming", "file": None, "line": None}])
        f = [x for x in r.findings if x.rule_id == "ext.agent.maybe-telemetry"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, "info")
        self.assertLessEqual(f[0].confidence, 0.3)
        self.assertEqual(f[0].evidence_class, "D")

    def test_path_traversal_is_rejected(self):
        r = run_scan([{"schema": 1, "producer": "semgrep", "class": "B", "command": "semgrep scan --config p/xss",
                       "type": "finding", "rule": "xss", "severity": "low", "confidence": 0.5, "title": "t",
                       "observation": "x", "file": "../../etc/passwd", "line": None}])
        self.assertIn("relative path", notes(r))
        self.assertFalse([x for x in r.findings if x.rule_id == "ext.semgrep.xss"])

    def test_unknown_producer_is_rejected(self):
        r = run_scan([base(producer="mystery")])
        self.assertIn("unknown producer", notes(r))

    def test_claim_without_matching_claim_is_rejected(self):
        r = run_scan([base(claim_category="popularity")])
        self.assertIn("no claim of category", notes(r))

    def test_malformed_line_does_not_crash(self):
        root = make_repo({"README.md": README, "src/a.js": "x\n"})
        head = git_init(root)
        ev = Path(tempfile.mkdtemp(prefix="ev-"))
        (ev / "rea.jsonl").write_text("{not json\n" + json.dumps(base(target_commit=head)) + "\n", encoding="utf-8")
        r = run_scan([], root=root, ev_dir=ev)
        self.assertIn("not valid JSON", notes(r))
        self.assertEqual(claim(r).status, "contradicted")

    def test_evidence_inside_repository_is_ignored(self):
        root = make_repo({"README.md": README, "src/a.js": "x\n"})
        ev = root / "evidence"
        ev.mkdir()
        (ev / "rea.jsonl").write_text(json.dumps(base()) + "\n", encoding="utf-8")
        r = run_scan([], root=root, ev_dir=ev)
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("inside the scanned repository", notes(r))

    def test_class_b_without_git_commit_is_rejected(self):
        root = make_repo({"README.md": README, "src/a.js": "x\n"})  # no git: nothing to bind to
        r = run_scan([base()], root=root)
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("needs a git commit", notes(r))

    def test_wrong_commit_is_rejected(self):
        root = make_repo({"README.md": README})
        head = git_init(root)
        r = run_scan([base(target_commit="deadbee")], root=root)
        self.assertNotEqual(claim(r).status, "contradicted")
        self.assertIn("different version", notes(r))
        r2 = run_scan([base(target_commit=head[:12])], root=root)  # abbreviated commit still matches
        self.assertEqual(claim(r2).status, "contradicted")

    def test_summary_is_reported(self):
        r = run_scan([base()])
        step = [s for s in r.steps if s.name == "claims"][0]
        self.assertEqual(step.data["evidence"]["accepted"], 1)
        self.assertEqual(step.data["evidence"]["by_class"]["B"], 1)
        self.assertTrue(any("producer-declared" in n for n in step.not_checked))


if __name__ == "__main__":
    unittest.main()
