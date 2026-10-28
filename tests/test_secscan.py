"""Unit tests for the runner's own logic (no scanners needed).  Run: make test"""
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from secscan import config, findings, report, suppress


def sarif(uri, line, rule="r1", level="error"):
    return {"runs": [{"tool": {"driver": {"rules": [{"id": rule}]}},
                      "results": [{"ruleId": rule, "level": level, "message": {"text": "m"},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                                       "region": {"startLine": line}}}]}]}]}


class Fingerprints(unittest.TestCase):
    def test_line_shift_keeps_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "a.py").write_text("x = 1\neval(y)\n")
            s = repo / "s.sarif"
            s.write_text(json.dumps(sarif("a.py", 2)))
            f1 = findings.from_sarif("semgrep", s, repo)[0]
            (repo / "a.py").write_text("# new\n# lines\nx = 1\neval(y)\n")
            s.write_text(json.dumps(sarif("a.py", 4)))
            f2 = findings.from_sarif("semgrep", s, repo)[0]
            self.assertEqual(f1["fingerprint"], f2["fingerprint"])
            self.assertEqual(f2["severity"], "high")

    def test_identical_lines_get_distinct_fingerprints(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "a.py").write_text("eval(y)\neval(y)\n")
            data = sarif("a.py", 1)
            data["runs"][0]["results"].append(json.loads(json.dumps(data["runs"][0]["results"][0])))
            data["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] = 2
            s = repo / "s.sarif"
            s.write_text(json.dumps(data))
            fs = findings.from_sarif("semgrep", s, repo)
            self.assertEqual(len({f["fingerprint"] for f in fs}), 2)

    def test_absolute_and_worktree_uris_are_made_relative(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "outer" / "wt"
            (repo / ".github").mkdir(parents=True)
            (repo / ".github" / "ci.yml").write_text("on: push\n")
            self.assertEqual(findings._rel_uri(f"file://{repo}/.github/ci.yml", repo), ".github/ci.yml")
            self.assertEqual(findings._rel_uri("outer/wt/.github/ci.yml", repo), ".github/ci.yml")

    def test_semgrep_rule_id_is_machine_independent(self):
        self.assertEqual(findings._norm_rule("semgrep", "home.u.x.tools.rules.semgrep-rules.python.a.b"), "python.a.b")


class Suppressions(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / suppress.FILENAME
            p.write_text(text)
            return suppress.load(p)

    def test_expiry(self):
        entries, errors = self._load(
            '[[accept]]\nrule="r1"\nreason="ok"\nexpires=2026-12-31\n'
            '[[accept]]\nrule="r2"\nreason="old"\nexpires=2026-01-01\n')
        self.assertEqual(errors, [])
        fs = [{"fingerprint": "a", "tool": "t", "rule": "r1", "path": "x"},
              {"fingerprint": "b", "tool": "t", "rule": "r2", "path": "x"}]
        suppress.apply(fs, entries, dt.date(2026, 10, 28))
        self.assertEqual(fs[0]["status"], "suppressed")
        self.assertEqual(fs[1]["status"], "active")
        self.assertEqual(fs[1]["suppression_expired"]["expires"], "2026-01-01")

    def test_invalid_entries_are_reported_not_applied(self):
        entries, errors = self._load('[[accept]]\nrule="r1"\nexpires=2027-01-01\n'
                                     '[[accept]]\nrule="r1"\nreason="x"\nexpires="2027-01-01"\n')
        self.assertEqual(entries, [])
        self.assertEqual(len(errors), 2)


class Lockfiles(unittest.TestCase):
    def test_detection(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
            (repo / "requirements.txt").write_text("lxml>=5.0\n")
            got, _ = findings.lockfile_findings(repo)
            self.assertEqual(sorted(f["path"] for f in got), ["pyproject.toml", "requirements.txt"])
            (repo / "requirements.txt").write_text("lxml==6.0.0 \\\n    --hash=sha256:abc\n")
            got, locks = findings.lockfile_findings(repo)
            self.assertEqual(got, [])
            self.assertEqual(locks, ["requirements.txt"])


class Diff(unittest.TestCase):
    def test_new_fixed_open_and_errored_tools(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            for p, fs, st in ((a, ["1", "2"], "ok"), (b, ["2", "3"], "ok")):
                p.mkdir()
                (p / "meta.json").write_text(json.dumps({"tools": {"semgrep": {"status": st}}}))
                (p / "findings.json").write_text(json.dumps(
                    [{"fingerprint": x, "status": "active", "tool": "semgrep", "severity": "high",
                      "path": "p", "rule": "r"} for x in fs]))
            res = report.diff(a, b)
            self.assertEqual([f["fingerprint"] for f in res["new"]], ["3"])
            self.assertEqual([f["fingerprint"] for f in res["fixed"]], ["1"])
            self.assertEqual([f["fingerprint"] for f in res["open"]], ["2"])
            (b / "meta.json").write_text(json.dumps({"tools": {"semgrep": {"status": "error"}}}))
            res = report.diff(a, b)
            self.assertEqual(res["fixed"], [])  # an errored tool never reports "fixed"
            self.assertEqual(res["not_compared_tools"], ["semgrep"])


class Registry(unittest.TestCase):
    def test_project_registry_loads(self):
        repos = config.load_registry(config.ROOT / "repos.toml")
        self.assertIn(("ComfyUI_OpenClip", "local"), [(r.name, r.mode) for r in repos])
        self.assertEqual(len({r.name for r in repos}), len(repos))  # names are unique

    def test_rejects_bad_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.toml"
            p.write_text('[[repo]]\nname="x"\ngithub="o/x"\nmode="cloud"\n')
            with self.assertRaises(ValueError):
                config.load_registry(p)


if __name__ == "__main__":
    unittest.main()
