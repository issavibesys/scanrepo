# scanrepo

Static scanner for repositories. It checks whether a project's claims are backed by its code, and looks for
known vulnerabilities, hardcoded secrets, risky code patterns, telemetry and insecure defaults.

**scanrepo never executes the code it scans.** It reads files, parses manifests and runs regex and
data-driven rules. Every result carries a confidence score and a "could not be checked" section, so a
clean report does not mean the project is safe.

## Use it

```bash
# local directory
python3 -m scanrepo ./some-project

# GitHub repository (cloned shallowly, hooks disabled)
python3 -m scanrepo owner/repo -o out/

# formats and gating
python3 -m scanrepo . -f json
python3 -m scanrepo . -f sarif -o out/
python3 -m scanrepo . --fail-on high --min-confidence 0.5   # exit 1 if a production finding is found
```

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` error.

### AI agents (MCP)

`python3 -m scanrepo.mcp_server` speaks MCP over stdio and exposes one tool, `scan_repo`.
Register it in your agent's MCP configuration as a stdio server with that command.

### GitHub Action

See `action.yml` and `examples/pr-scan.yml`. Pin the action to a full commit SHA in your workflows.
The example uses the `pull_request` trigger, which runs without repository secrets. Do not switch it to
`pull_request_target` while the job checks out or runs pull request code.

## What it checks

| Step | Question it answers |
|---|---|
| 1. Inventory | What is in the repository? Languages, manifests, license, CI, committed binaries, git provenance. |
| 2. Claims | Are README claims ("zero dependencies", "audited", "no telemetry", "10x faster") backed by evidence? |
| 3. Dependencies | Install-time scripts, git/URL sources, typosquat-like names, and known vulnerabilities (osv-scanner or npm audit, if installed). |
| 4. Static analysis | Hardcoded secrets, risky code patterns (`eval`, `shell=True`, Electron flags, weak hashes). |
| 5. Behaviour (static) | Outbound hosts, telemetry SDKs and endpoints, TLS verification disabled by default, hidden features, obfuscation. |
| 6. Report | Markdown, JSON and SARIF, with severity, confidence, exact location and a list of what was not checked. |

Claim statuses mean:

- `supported`: positive evidence was found.
- `no_contradiction_found`: a negative claim ("no telemetry") that the scan found nothing against. This is not proof.
- `unsupported`: no evidence either way.
- `contradicted`: the repository contains evidence against the claim.

## Limits

- Heuristics, not data-flow analysis. A hit shows where to look.
- Runtime behaviour and encrypted traffic cannot be observed statically.
- Known-vulnerability lookup needs `osv-scanner` or `npm` on the PATH. Without them the report says so.
- Git history is only checked for metadata, not for secrets deleted in later commits.
- Text in reports comes from the scanned repository and is untrusted data.
- Rules live in `scanrepo/data/rules.json`. Files that contain the rule patterns themselves (such as the
  rules file or this tool's own source) produce expected hits when you scan this project.

## Add evidence from other tools

Tools can write evidence records into a directory outside the repository, and scanrepo validates them:

```bash
python3 -m scanrepo ./project --evidence ./evidence
```

Each record is one JSON object (see `scanrepo/evidence.py` and `examples/evidence/`). scanrepo decides what a record
may change:

- **Commit binding.** `target_commit` must match the scanned commit, so evidence cannot be reused on another version.
- **Command allowlist.** Class B needs a static command on the allowlist for its producer. Runtime and capture
  actions are refused even if they are otherwise allowed.
- **Classes.** Class A (runtime) is refused in this version. Class C (pattern) and D (hypothesis) cannot contradict a claim.
  Only class B can.
- **Location.** Files must be relative paths to existing files inside the repository.

Evidence is producer-declared. scanrepo checks the format and the rules above, but it does not verify that the
producer really ran its command.

### REA converter

`scanrepo/converters/rea.py` turns the JSON output of REA's static command into evidence records:

```bash
npx -y rea-agents@latest analyze-javascript-application /path/to/app --json > rea.json
python3 -m scanrepo.converters.rea rea.json --root /path/to/repo --out evidence/rea.jsonl
python3 -m scanrepo /path/to/repo --evidence evidence
```

The converter reads explicit `BrowserWindow` web preferences such as `nodeIntegration: true` as class B findings,
with the file and line REA reports. Dynamic values become class C leads. The field names come from REA's source;
the output envelope is searched for rather than assumed, so run it on real output before you rely on it.

## Extend the rules

```bash
python3 -m scanrepo . --rules my-rules.json
```

The file has the same structure as `scanrepo/data/rules.json`. Rules with an existing `id` override the built-in rule.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## License

MIT
