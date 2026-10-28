"""security-scans CLI.  Usually called through the Makefile.

  python -m secscan scan    [--registry repos.toml] [--repo NAME]
  python -m secscan diff    [--registry repos.toml] [--repo NAME] [--from RUN --to RUN]
  python -m secscan triage  [--registry repos.toml] --repo NAME [--run RUN]
  python -m secscan list    [--registry repos.toml]
  # CI building blocks (used by .github/workflows/scan.yml):
  python -m secscan scan-path --path DIR --name NAME --out DIR [--languages python,c]
                              [--gitleaks-log-opts OPTS] [--suppressions FILE] [--skip-tools gitleaks]
                              [--exclude third_party,vendor]
  python -m secscan compare --base RUN --head RUN [--fail-on high]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config, report, runner

DEFAULT_REGISTRY = config.ROOT / "repos.toml"


def _repos(args) -> list[config.Repo]:
    repos = config.load_registry(Path(args.registry))
    if args.repo:
        repos = [r for r in repos if r.name == args.repo]
        if not repos:
            sys.exit(f"repo {args.repo!r} not in {args.registry}")
    return repos


def cmd_scan(args) -> int:
    rc = 0
    repos = _repos(args)
    runner.log("repos to scan: " + ", ".join(f"{r.name} ({r.mode})" for r in repos))
    for r in repos:
        runner.log(f"== {r.name}: syncing {r.url}")
        clone = runner.sync(r)
        run_dir = runner.new_run_dir(r.name)
        sup = (config.ROOT / r.suppressions) if r.suppressions else None
        meta = runner.scan_path(clone, r.name, run_dir, r.languages, "--all", sup,
                                extra_meta={"url": r.url, "mode": r.mode}, exclude=r.exclude)
        d = report.write_diff(report.previous_run(run_dir, r.name), run_dir)
        report.write_summary(run_dir, d)
        errors = [t for t, s in meta["tools"].items() if s["status"] == "error"]
        if errors:
            rc = 1
        runner.log(f"   {r.name} @ {meta['commit'][:12]}: new {len(d['new'])}, fixed {len(d['fixed'])}, "
                   f"open {len(d['open'])}" + (f"; TOOL ERRORS: {errors}" if errors else ""))
        runner.log(f"   report: {run_dir}/summary.md")
    return rc


def cmd_diff(args) -> int:
    if args.to:
        cur = Path(args.to).resolve()
        prev = Path(args.from_).resolve() if args.from_ else report.previous_run(cur, cur.parent.name)
        d = report.write_diff(prev, cur)
        print(report.diff_markdown(d))
        return 0
    for r in _repos(args):
        runs = report.runs_for(r.name)
        if not runs:
            runner.log(f"{r.name}: no runs yet")
            continue
        d = report.write_diff(runs[-2] if len(runs) > 1 else None, runs[-1])
        report.write_summary(runs[-1], d)
        print(report.diff_markdown(d))
    return 0


def cmd_triage(args) -> int:
    from . import triage
    (r,) = _repos(args)
    run = Path(args.run).resolve() if args.run else (report.runs_for(r.name) or [None])[-1]
    if run is None:
        sys.exit(f"{r.name}: no scan runs; run make scan first")
    triage.triage(run, config.WORK / r.name, model=args.model, budget=args.budget)
    return 0


def cmd_list(args) -> int:
    for r in _repos(args):
        print(f"{r.name}\t{r.mode}\t{','.join(r.languages)}\t{r.url}")
    return 0


def cmd_scan_path(args) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    meta = runner.scan_path(Path(args.path).resolve(), args.name, out,
                            [x for x in args.languages.split(",") if x], args.gitleaks_log_opts,
                            Path(args.suppressions).resolve() if args.suppressions else None,
                            skip=frozenset(x for x in args.skip_tools.split(",") if x),
                            exclude=[x for x in args.exclude.split(",") if x])
    report.write_summary(out, None)
    return 1 if any(s["status"] == "error" for s in meta["tools"].values()) else 0


def cmd_compare(args) -> int:
    d, failing = report.compare_for_ci(Path(args.base).resolve(), Path(args.head).resolve(), args.fail_on)
    report.write_summary(Path(args.head).resolve(), d)
    print(report.diff_markdown(d))
    if d["not_compared_tools"]:
        runner.log(f"tools that errored (not compared): {d['not_compared_tools']}")
        return 2
    if failing:
        runner.log(f"{len(failing)} new finding(s) at or above '{args.fail_on}'")
        return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secscan")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "diff", "triage", "list"):
        s = sub.add_parser(name)
        s.add_argument("--registry", default=str(DEFAULT_REGISTRY))
        s.add_argument("--repo")
    sub.choices["diff"].add_argument("--from", dest="from_")
    sub.choices["diff"].add_argument("--to")
    sub.choices["triage"].add_argument("--run")
    sub.choices["triage"].add_argument("--model", default="sonnet")
    sub.choices["triage"].add_argument("--budget", default="1.50", help="max USD for the claude call")
    s = sub.add_parser("scan-path")
    s.add_argument("--path", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--languages", default="")
    s.add_argument("--gitleaks-log-opts", default="--all")
    s.add_argument("--suppressions")
    s.add_argument("--skip-tools", default="", help="comma list; only 'gitleaks' is supported")
    s.add_argument("--exclude", default="", help="comma list of paths kept out of SAST")
    s = sub.add_parser("compare")
    s.add_argument("--base", required=True)
    s.add_argument("--head", required=True)
    s.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"])
    args = p.parse_args(argv)
    return {"scan": cmd_scan, "diff": cmd_diff, "triage": cmd_triage, "list": cmd_list,
            "scan-path": cmd_scan_path, "compare": cmd_compare}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
