# Detection design and tuning

The unit of correlation is `(normalized source IP, exact username)`. IPv6 spelling is canonicalized; usernames are intentionally case-sensitive because identity-provider semantics differ. The detector retains recent failures for a pair, evaluates at each event, and suppresses repeat alerts per rule/pair within a batch. Threshold and window are configurable:

```sh
python detector.py data/auth-demo.jsonl --threshold 3 --window-seconds 120
```

AUTH-001 evaluates on failure; AUTH-002 evaluates on success. Failures remain available after success. This favors a simple audit trail but can associate old typos with later legitimate activity. Timestamps with equal values are ordered lexically by ID, so use higher-resolution timestamps or a source sequence adapter if order matters.

## Tuning experiment

Start with an approved, sanitized baseline. Count alerts per user/source/day, label a review sample with supporting context, and compare thresholds. Record false positives and missed labeled scenarios separately. Do not infer precision or recall from this tiny synthetic fixture. Raising thresholds reduces sensitivity; shortening the window can miss slow attacks. Prefer explicit scoped exceptions with review dates over global source allowlists.

## Test strategy

The suite covers threshold crossing, below-threshold activity, inclusive/exclusive time boundaries, expired history before success, separate source/user groups, deterministic sorting, suppression, timezone conversion, malformed records, duplicate IDs, configuration, and CLI output/error contracts. Additional tests should cover any new normalization adapter and its missing-field behavior.

## Operational gap

A production implementation needs bounded state, identity and tenant scoping, ingestion guarantees, cross-run deduplication, telemetry access controls, privacy review, and alert delivery monitoring. This code performs no response actions. No ATT&CK technique coverage or SIEM compatibility is claimed.
