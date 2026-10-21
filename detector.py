"""Offline, deterministic authentication detections. Python standard library only."""
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import sys


def load_events(path):
    events = []
    seen = set()
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("expected an object")
                for key in ("event_id", "timestamp", "src_ip", "user", "outcome"):
                    if not isinstance(row.get(key), str) or not row[key].strip():
                        raise ValueError(f"{key} must be a nonempty string")
                if row["event_id"] in seen:
                    raise ValueError("duplicate event_id")
                if row["outcome"] not in ("failure", "success"):
                    raise ValueError("outcome must be failure or success")
                stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    raise ValueError("timestamp must include timezone")
                row = {key: row[key] for key in ("event_id", "src_ip", "user", "outcome")}
                row["src_ip"] = str(ipaddress.ip_address(row["src_ip"]))
                row["time"] = stamp.astimezone(timezone.utc)
                seen.add(row["event_id"])
                events.append(row)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"line {number}: {exc}") from exc
    return sorted(events, key=lambda event: (event["time"], event["event_id"]))


def detect(events, threshold=5, window_seconds=300):
    """Emit once per rule/group per batch; windows include both endpoints."""
    if type(threshold) is not int or threshold < 2:
        raise ValueError("threshold must be an integer >= 2")
    if type(window_seconds) is not int or window_seconds < 1:
        raise ValueError("window_seconds must be a positive integer")
    failures = defaultdict(list)
    emitted = set()
    alerts = []
    for event in sorted(events, key=lambda e: (e["time"], e["event_id"])):
        key = (event["src_ip"], event["user"])
        start = event["time"] - timedelta(seconds=window_seconds)
        failures[key] = [old for old in failures[key] if old["time"] >= start]
        if event["outcome"] == "failure":
            failures[key].append(event)
            rule = "AUTH-001"
        else:
            rule = "AUTH-002"
        if len(failures[key]) >= threshold and (rule, key) not in emitted:
            evidence = failures[key] + ([event] if rule == "AUTH-002" else [])
            alerts.append({
                "rule_id": rule,
                "severity": "medium" if rule == "AUTH-001" else "high",
                "src_ip": key[0], "user": key[1],
                "observed_at": event["time"].isoformat(),
                "failure_count": len(failures[key]),
                "evidence_ids": [item["event_id"] for item in evidence],
            })
            emitted.add((rule, key))
    return alerts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="normalized JSONL authentication events")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        alerts = detect(load_events(args.input), args.threshold, args.window_seconds)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for alert in alerts:
        print(json.dumps(alert, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
