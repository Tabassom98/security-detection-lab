# Authentication Detection Lab

An offline Python lab that turns normalized authentication logs into explainable alerts. Built as a starter portfolio project for learning detection engineering: define a hypothesis, implement it, test its boundaries, and document how an analyst should investigate it.

**Scope:** synthetic data, two transparent rules, no external services or dependencies. This is an AI-assisted educational implementation, not evidence of production deployment, incident response experience, or measured real-world detection accuracy.

## Run in two minutes

Requires Python 3.10 or newer. From this repository's directory on Windows, macOS, or Linux:

```sh
python detector.py data/auth-demo.jsonl
python -m unittest discover -s tests -v
```

If your system uses `python3`, substitute it for `python`. No administrator rights, API keys, pip installs, or network access are required. The demo prints two JSON alerts, matching [the expected output](examples/expected-alerts.jsonl). Exit 0 means the analysis completed, even with alerts; exit 2 means an input or configuration error. Redirect stdout if you want to save a report.

## Detections

| Rule | Hypothesis | Default logic | Severity |
| --- | --- | --- | --- |
| AUTH-001 | Repeated failures may indicate password guessing | At least 5 failures for the same source IP and username within 300 seconds | Medium |
| AUTH-002 | A success after repeated failures deserves review | A successful login for that same pair with at least 5 preceding failures within 300 seconds | High |

Both endpoints of the time window count. Events are sorted by UTC timestamp, then event ID; equal-time order is therefore deterministic but may differ from actual occurrence order. Each rule emits at most once per IP/user pair **per invocation**. A success does not reset failure history. Counts describe the window at first trigger, not the whole file. Evidence IDs make each alert traceable to source events.

## Data contract

One JSON object per line, with nonempty string fields `event_id`, `timestamp`, `src_ip`, `user`, and `outcome`. IDs must be unique in a file. Timestamp must be ISO 8601 with a timezone; IP must be a valid IPv4 or IPv6 literal; outcome must be `failure` or `success`. Extra fields are ignored. Blank lines are allowed. Invalid records fail the entire run before any alerts are printed.

```json
{"event_id":"demo-01","timestamp":"2026-01-01T00:00:00Z","src_ip":"192.0.2.10","user":"demo-user","outcome":"failure"}
```

The fixture is hand-authored synthetic telemetry using documentation IP ranges. It contains a five-failure burst followed by a success and an unrelated benign login. It contains no credentials or customer data. Native Windows, SSH, cloud identity, and SIEM formats need a normalization adapter before use.

## Investigate an alert

1. Confirm the source events and timestamps; check ingestion duplication and clock quality.
2. Identify the account owner, host/service, VPN/NAT context, and whether the activity was expected.
3. Review MFA and session telemetry, nearby activity, and approved maintenance before deciding whether compromise is plausible.
4. Record evidence and follow your organization's escalation process. This tool never blocks an IP or disables an account.

See [rule design and tuning](docs/detection-design.md), [the synthetic case walkthrough](docs/case-study.md), and [the learning guide](docs/learning-guide.md).

## Limitations

Password typos, stale service credentials, and shared networks can trigger these rules. Distributed guessing, password spraying across many users, and slow attempts can evade them. A successful login does not prove compromise. There is no MFA context, device identity, enrichment, streaming state, cross-run suppression, or production performance benchmark. The whole input is held in memory; this implementation is intended for small lab files. Tests establish behavior on fixtures, not real-world accuracy.

## Repository map

- `detector.py`: validation, UTC normalization, correlation, and CLI.
- `data/`: synthetic input; `examples/`: reproducible expected alerts.
- `tests/`: positive, negative, boundary, validation, ordering, and CLI tests.
- `.github/workflows/tests.yml`: proposed automated checks on Linux and Windows. A passing remote CI run must be verified after publication; none is claimed here.

## Development and provenance

Created with AI assistance for Tabassom Azmi's starter portfolio. Code and documentation were generated and locally exercised as part of setup. Personal understanding, independent implementation, production use, and prior accomplishments are not implied. Future changes should record a hypothesis and include a test that distinguishes correct behavior from a plausible bug.

Planned extensions: distinct-user password-spray detection; a real log normalization adapter using sanitized samples; richer analyst context; then a separate AI security lab evaluating untrusted-input handling. These are plans, not completed features.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT licensed.
