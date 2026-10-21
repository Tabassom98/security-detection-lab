import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from detector import detect, load_events


def event(i, seconds=0, outcome="failure", ip="192.0.2.10", user="demo"):
    return dict(event_id=str(i), timestamp=f"2026-01-01T00:{seconds // 60:02}:{seconds % 60:02}Z",
                src_ip=ip, user=user, outcome=outcome)


class DetectionTests(unittest.TestCase):
    def load(self, rows):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            return load_events(path)

    def test_below_threshold(self):
        self.assertEqual(detect(self.load([event(i, i) for i in range(4)])), [])

    def test_threshold_and_success(self):
        alerts = detect(self.load([event(i, i) for i in range(5)] + [event(5, 5, "success")]))
        self.assertEqual([a["rule_id"] for a in alerts], ["AUTH-001", "AUTH-002"])
        self.assertEqual(alerts[1]["evidence_ids"], [str(i) for i in range(6)])

    def test_inclusive_boundary(self):
        rows = [event(i, i) for i in range(4)] + [event(4, 300)]
        self.assertEqual(len(detect(self.load(rows))), 1)

    def test_expired_boundary(self):
        rows = [event(i, i) for i in range(4)] + [event(4, 301)]
        self.assertEqual(detect(self.load(rows)), [])

    def test_group_isolation(self):
        rows = [event(i, i) for i in range(4)] + [event(4, 4, ip="192.0.2.11"), event(5, 5, user="other")]
        self.assertEqual(detect(self.load(rows)), [])

    def test_sort_and_batch_suppression(self):
        rows = [event(i, i) for i in range(9)]
        self.assertEqual(detect(self.load(rows)), detect(self.load(rows[::-1])))
        self.assertEqual(len(detect(self.load(rows))), 1)

    def test_success_without_failures(self):
        self.assertEqual(detect(self.load([event(1, outcome="success")])), [])

    def test_old_failures_do_not_match_success(self):
        rows = [event(i, i) for i in range(5)] + [event(5, 400, "success")]
        self.assertEqual([a["rule_id"] for a in detect(self.load(rows))], ["AUTH-001"])

    def test_invalid_records(self):
        for field, value in [("src_ip", "bad"), ("outcome", "unknown"), ("user", ""),
                             ("timestamp", "2026-01-01T00:00:00"), ("event_id", 1)]:
            with self.subTest(field=field):
                row = event(0)
                row[field] = value
                with self.assertRaisesRegex(ValueError, "line 1"):
                    self.load([row])

    def test_duplicate_id(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.load([event(0), event(0)])

    def test_bad_json_and_nonobject(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.jsonl"
            for text in ("{", "[]", "null"):
                path.write_text(text, encoding="utf-8")
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, "line 1"):
                    load_events(path)

    def test_empty(self):
        self.assertEqual(detect(self.load([])), [])

    def test_configuration(self):
        for kwargs in ({"threshold": 1}, {"window_seconds": 0}):
            with self.assertRaises(ValueError):
                detect([], **kwargs)

    def test_timezone_normalization(self):
        row = event(0)
        row["timestamp"] = "2026-01-01T01:00:00+01:00"
        self.assertEqual(self.load([row])[0]["time"].hour, 0)

    def test_demo_cli_matches_committed_output(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, "detector.py", "data/auth-demo.jsonl"],
                                cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (root / "examples/expected-alerts.jsonl").read_text(encoding="utf-8")
        self.assertEqual(result.stdout, expected)

    def test_cli_errors_are_not_partial_results(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.jsonl"
            path.write_text("{}", encoding="utf-8")
            result = subprocess.run([sys.executable, str(root / "detector.py"), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("line 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
