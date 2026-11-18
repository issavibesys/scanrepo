import json
import tempfile
import unittest
from pathlib import Path

from scanrepo import evidence as ev
from scanrepo.context import ScanOptions
from scanrepo.converters.rea import convert, main as convert_main
from scanrepo.engine import scan

from .gitutil import git_init
from .test_scan import make_repo

COMMIT = "e7a104665cf0557ce71e3f68fd0e78ee485b2d2c"


def lit(name, value):
    return {"name": name, "value": {"status": "literal", "value": value, "expression": None}}


def dyn(name, expr):
    return {"name": name, "value": {"status": "dynamic", "value": None, "expression": expr}}


def doc(files):
    """Envelope deliberately wrapped, so the converter must search for the entries."""
    return {"ok": True, "value": {"analysis": {"files": files}}}


def win(prefs, line=3, ctor=None):
    w = {"options_status": "object-literal", "web_preferences_status": "object-literal",
         "web_preferences": prefs, "module_key": None, "location": {"start": {"line": line, "column": 1}, "end": {"line": line, "column": 9}}}
    if ctor:
        w["window_constructor"] = ctor
    return w


def entry(file, windows):
    return {"file": file, "javascript": {"electron": {"browser_windows": windows}}}


class ReaConverterTest(unittest.TestCase):
    def setUp(self):
        self.root = make_repo({"src/main.js": "x\n" * 5, "src/view.js": "y\n", "package.json": "{}"})
        self.head = git_init(self.root)

    def test_literal_node_integration_is_class_b_with_line(self):
        recs, stats = convert(doc([entry(str(self.root / "src/main.js"), [win([lit("nodeIntegration", True)], line=4)])]),
                              self.root, COMMIT)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual((r["class"], r["rule"], r["file"], r["line"]), ("B", "electron-node-integration", "src/main.js", 4))
        self.assertEqual(r["producer"], "rea")
        self.assertEqual(r["command"], "analyze-javascript-application --json")
        self.assertEqual(r["target_commit"], COMMIT)

    def test_literal_false_insecure_setting(self):
        recs, _ = convert(doc([entry("src/view.js", [win([lit("contextIsolation", False)])])]), self.root, COMMIT)
        self.assertEqual([r["rule"] for r in recs], ["electron-context-isolation-off"])
        self.assertEqual(recs[0]["class"], "B")

    def test_secure_values_produce_nothing(self):
        recs, _ = convert(doc([entry("src/view.js", [win([lit("nodeIntegration", False), lit("contextIsolation", True)])])]),
                          self.root, COMMIT)
        self.assertEqual(recs, [])

    def test_dynamic_value_is_class_c_lead_not_proof(self):
        recs, _ = convert(doc([entry("src/view.js", [win([dyn("nodeIntegration", "isDev ? true : false")])])]), self.root, COMMIT)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["class"], "C")
        self.assertLessEqual(recs[0]["confidence"], 0.3)

    def test_zero_is_not_false(self):
        recs, _ = convert(doc([entry("src/view.js", [win([lit("contextIsolation", 0)])])]), self.root, COMMIT)
        self.assertEqual(recs, [])

    def test_omitted_preferences_are_not_reported(self):
        recs, _ = convert(doc([entry("src/view.js", [win([])])]), self.root, COMMIT)
        self.assertEqual(recs, [])

    def test_absolute_path_outside_repo_is_skipped(self):
        outside = tempfile.mkdtemp()
        recs, stats = convert(doc([entry(str(Path(outside) / "x.js"), [win([lit("nodeIntegration", True)])])]), self.root, COMMIT)
        self.assertEqual(recs, [])
        self.assertEqual(stats["unresolved_files"], 1)

    def test_view_constructor_is_named_in_observation(self):
        recs, _ = convert(doc([entry("src/view.js", [win([lit("sandbox", False)], ctor="BrowserView")])]), self.root, COMMIT)
        self.assertIn("BrowserView", recs[0]["observation"])

    def test_every_record_passes_the_scanner_contract(self):
        recs, _ = convert(doc([entry("src/main.js", [win([lit("nodeIntegration", True), dyn("sandbox", "s")])])]),
                          self.root, COMMIT)
        cats = set()
        for r in recs:
            checked, why = ev._check(r, self.root, COMMIT, cats)
            self.assertIsNotNone(checked, why)

    def test_cli_rejects_non_analysis_input(self):
        inp = Path(tempfile.mkdtemp()) / "in.json"
        inp.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
        out = Path(tempfile.mkdtemp()) / "rea.jsonl"
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            code = convert_main([str(inp), "--root", str(self.root), "--out", str(out), "--commit", COMMIT])
        self.assertEqual(code, 2)

    def test_cli_refuses_output_inside_repo(self):
        inp = Path(tempfile.mkdtemp()) / "in.json"
        inp.write_text(json.dumps(doc([entry("src/view.js", [win([lit("nodeIntegration", True)])])])), encoding="utf-8")
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            code = convert_main([str(inp), "--root", str(self.root), "--out", str(self.root / "ev" / "rea.jsonl"), "--commit", COMMIT])
        self.assertEqual(code, 2)

    def test_end_to_end_converter_then_scanner(self):
        inp = Path(tempfile.mkdtemp()) / "in.json"
        inp.write_text(json.dumps(doc([entry("src/main.js", [win([lit("nodeIntegration", True)], line=2)])])), encoding="utf-8")
        evdir = Path(tempfile.mkdtemp())
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            code = convert_main([str(inp), "--root", str(self.root), "--out", str(evdir / "rea.jsonl"), "--commit", self.head])
        self.assertEqual(code, 0)
        report = scan(str(self.root), ScanOptions(use_external=False, evidence_dir=str(evdir)))
        f = [x for x in report.findings if x.rule_id == "ext.rea.electron-node-integration"]
        self.assertTrue(f)
        self.assertEqual((f[0].evidence_class, f[0].file, f[0].line), ("B", "src/main.js", 2))
        self.assertIn("rea", f[0].verified_by[0])

    def test_converter_output_for_other_commit_is_rejected_by_scanner(self):
        inp = Path(tempfile.mkdtemp()) / "in.json"
        inp.write_text(json.dumps(doc([entry("src/main.js", [win([lit("nodeIntegration", True)])])])), encoding="utf-8")
        evdir = Path(tempfile.mkdtemp())
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            convert_main([str(inp), "--root", str(self.root), "--out", str(evdir / "rea.jsonl"), "--commit", COMMIT])
        report = scan(str(self.root), ScanOptions(use_external=False, evidence_dir=str(evdir)))
        self.assertFalse([x for x in report.findings if x.rule_id == "ext.rea.electron-node-integration"])
        self.assertIn("different version", " | ".join(n for s in report.steps for n in s.notes))


if __name__ == "__main__":
    unittest.main()
