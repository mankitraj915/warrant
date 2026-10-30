"""Decision trace: explain one run from its audit row (Phase 2 step 7).

Reads only the ``audit`` table. Evaluation runs use in-memory databases, so the
harness copies each run's audit rows into ``results/audit.sqlite``
(``copy_audit``); this CLI reads from there by default.

Usage: ``python -m evals.trace <run_id> [--db PATH]``.
"""

import argparse
import json
import sqlite3
import sys
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path
from typing import Any

DEFAULT_DB = Path("results/audit.sqlite")


def audit_rows(src: sqlite3.Connection) -> list[tuple[str, str]]:
    return src.execute("SELECT run_id, record FROM audit ORDER BY id").fetchall()


def write_audit(rows: Iterable[tuple[str, str]], dest: Path) -> None:
    """Append audit rows to the audit table in ``dest``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(dest)) as out:
        out.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, run_id, record)")
        out.executemany("INSERT INTO audit (run_id, record) VALUES (?, ?)", rows)
        out.commit()


def copy_audit(src: sqlite3.Connection, dest: Path) -> None:
    """Append every audit row of ``src`` to the audit table in ``dest``."""
    write_audit(audit_rows(src), dest)


def _call(action: dict[str, Any]) -> str:
    args = ", ".join(f"{k}={v}" for k, v in sorted(action["args"].items()))
    return f"{action['tool']}({args})"


def _origins(origins: list[str] | str) -> str:
    return origins if isinstance(origins, str) else ", ".join(origins) or "trusted"


def render(db: sqlite3.Connection, run_id: str) -> str:
    row = db.execute("SELECT record FROM audit WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        return f"no audit record for run {run_id}"
    r = json.loads(row[0])
    lines = [f"run {run_id}: {r['outcome']}" + (f" ({r['reason']})" if r["reason"] else "")]
    if r.get("task_id"):
        lines.append(f"task: {r['task_id']}")
    lines.append(f"planner input hash: {r['planner_input_hash']}")
    lines.append(f"plan label: {_origins(r['plan_label'])}")
    lines.append(f"actions ({len(r['actions'])}):")
    rules = {tuple(d["site"]): d for d in r["rules"]}
    for action, verdict in zip(r["actions"], r["verdicts"], strict=True):
        lines.append(f"  [{'.'.join(map(str, action['site']))}] {_call(action)}")
        for name, origins in sorted(action["labels"].items()):
            lines.append(f"      {name} <- {_origins(origins)}")
        by = f" by {verdict['rule']}" if verdict["rule"] else ""
        lines.append(f"      verdict: {verdict['kind']}{by}: {verdict['reason']}")
        decision = rules.get(tuple(action["site"]))
        if decision is not None:
            outcome = "admitted" if decision["admitted"] else "rejected"
            lines.append(f"      rule {decision['rule']}: {outcome} ({decision['reason']})")
    if r["approval_hash"] is not None:
        lines.append(f"approval requested: hash {r['approval_hash']}")
        lines.append(f"approved: {'yes' if r['approved'] else 'no'}")
    for x in r["executed"]:
        lines.append(f"executed: {x['tool']} key={x['key']} ref={x['provider_ref']}")
    if r.get("answer_sinks"):
        lines.append(f"answer sinks: {', '.join(r['answer_sinks'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = parser.parse_args(argv)
    if not args.db.exists():
        print(f"no audit database at {args.db}; run `tasks.py eval` first", file=sys.stderr)
        return 1
    with closing(sqlite3.connect(args.db)) as db:
        text = render(db, args.run_id)
    print(text)
    return 1 if text.startswith("no audit record") else 0


if __name__ == "__main__":
    sys.exit(main())
