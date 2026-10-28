"""On-demand AI triage with Claude Code headless, read-only.

How read-only / no-credentials is enforced (flags from `claude --help`, v2.1.281):
  --tools Read,Grep,Glob      only these built-in tools exist in the session
  --disallowedTools ...       belt and braces: deny the write/exec/network tools by name
  --restricted                ignores user/project/local settings files, confines file
                              tools to the working dirs (+ --add-dir), refuses
                              bypassPermissions
  --safe-mode                 no CLAUDE.md, skills, plugins, hooks, MCP servers, custom agents
  --strict-mcp-config         (no --mcp-config given) -> no MCP servers at all
  --permission-mode dontAsk + --permission-prompts none
                              anything that would need approval is denied, never asked
  --no-session-persistence    nothing saved for resume
  cwd = <run>/triage (inputs only), --add-dir <clone>: nothing else is readable
  environment: rebuilt from scratch (HOME, PATH, LANG, USER, TERM only), so no
  GH_TOKEN / cloud keys / SSH agent socket reach the process. Claude Code's own
  login (in ~/.claude) is used for the API call itself.
Claude writes nothing: its stdout (JSON) is parsed here and the Markdown written
by this script.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from . import report
from .runner import _git, log

READ_ONLY_TOOLS = "Read,Grep,Glob"
DENIED = ["Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Agent"]


def build_command(prompt: str, clone: Path, model: str, budget: str) -> list[str]:
    return [
        "claude", "-p", prompt,
        "--tools", READ_ONLY_TOOLS,
        "--disallowedTools", *DENIED,
        "--restricted", "--safe-mode", "--strict-mcp-config",
        "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--no-session-persistence", "--disable-slash-commands",
        "--add-dir", str(clone),
        "--model", model, "--max-budget-usd", budget,
        "--output-format", "json",
    ]


def triage(run_dir: Path, clone: Path, model: str = "sonnet", budget: str = "1.50") -> Path:
    meta, fs = report.load_run(run_dir)
    head = _git("rev-parse", "HEAD", cwd=clone)
    if head != meta["commit"]:
        raise SystemExit(f"clone {clone} is at {head[:12]}, run was {meta['commit'][:12]}: re-run make scan first")
    ws = run_dir / "triage"
    ws.mkdir(exist_ok=True)
    active = [f for f in fs if f["status"] == "active"]
    (ws / "findings.json").write_text(json.dumps(active, indent=1))
    shutil.copy(run_dir / "summary.md", ws / "summary.md")

    tmpl = (Path(__file__).parent / "triage_prompt.md").read_text()
    prompt = tmpl.format(repo=meta["repo"], commit=meta["commit"], short=meta["commit"][:12], clone=clone)
    cmd = build_command(prompt, clone, model, budget)
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LANG", "USER", "TERM") if k in os.environ}
    (ws / "command.json").write_text(json.dumps({"cmd": cmd[:2] + ["<prompt: secscan/triage_prompt.md>"] + cmd[3:],
                                                 "cwd": str(ws), "env_keys": sorted(env)}, indent=1))
    log(f"triage: claude -p over {len(active)} findings (model={model}, budget=${budget})")
    p = subprocess.run(cmd, cwd=ws, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    (ws / "claude.stderr.log").write_text(p.stderr)
    try:
        res = json.loads(p.stdout)
    except json.JSONDecodeError:
        (ws / "claude.stdout.txt").write_text(p.stdout)
        raise SystemExit(f"claude failed (exit {p.returncode}); see {ws}")
    (ws / "claude.result.json").write_text(json.dumps({k: v for k, v in res.items() if k != "result"}, indent=1))
    if res.get("is_error") or p.returncode != 0:
        raise SystemExit(f"claude reported an error (exit {p.returncode}); see {ws}/claude.result.json")
    out = run_dir / "triage.md"
    out.write_text(res.get("result", "").strip() + "\n")
    log(f"triage report: {out} (cost ${res.get('total_cost_usd', '?')})")
    return out
