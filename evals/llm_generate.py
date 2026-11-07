"""Generation: raw model output as JSONL (SPEC_v1.1 §5). Needs the model; runs only on Actions.

It reads no scoring output, and scoring reads nothing from it but the records. Each record is
flushed as it is written, and a key already in the file is skipped, so a job can die and be
re-run, and a written record stays final. A process that generates a ``warrant`` plan refuses any
job carrying ticket text, so that plan cannot depend on injected text through retained model state.

Usage: ``python -m evals.llm_generate pilot --model granite --model-path FILE --out DIR``. The
full design's prompts carry ticket text, so tokenizing them is its own mode and its own process:
``python -m evals.llm_generate lengths ...``.
"""

import argparse
import ctypes
import json
import os
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evals.harness import injections
from evals.llm_pins import (
    FULL_SEEDS,
    MIN_AVAILABLE_BYTES,
    MODELS,
    PILOT_SEEDS,
    PILOT_TASKS,
    ModelPin,
)
from evals.llm_score import run_instance
from evals.tasks import UserTask
from evals.tasks.dev import USER_TASKS
from evals.yardstick import placebo_payload
from kernel.run import PlannerInput
from planners.llm_local import LocalModel, generation_key, render_messages, render_prompt

TASKS = {t.id: t for t in USER_TASKS}
# What this process has generated from: a warrant job, or a job carrying ticket text (§5).
_PROCESS_SAW: set[str] = set()


class MemoryRefused(Exception):
    """Too little memory to start: §2 refuses rather than swap."""


class Model(Protocol):
    def tokenize(self, prompt: str) -> list[int]: ...

    def generate(self, prompt: str, seed: int, *, reset: bool = True) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Job:
    family: str
    task: str
    injection: str | None
    seed: int
    planner_input: PlannerInput


class _Recording:
    """Takes the input from the real code path, so a key is the one replay will compute."""

    def __init__(self) -> None:
        self.seen: PlannerInput | None = None

    def plan(self, planner_input: PlannerInput) -> dict[str, Any]:
        self.seen = planner_input
        return {}


def planner_input(task: UserTask, payload: str | None, family: str) -> PlannerInput:
    recording = _Recording()
    run_instance(task, payload, family, recording, "input")
    assert recording.seen is not None
    return recording.seen


def pilot_jobs() -> list[Job]:
    """§9: five tasks, three seeds, ``warrant+llm`` only."""
    return [
        Job("warrant", name, None, seed, planner_input(TASKS[name], None, "warrant"))
        for name in PILOT_TASKS
        for seed in PILOT_SEEDS
    ]


def _distinct(jobs: Iterable[Job], template: str) -> list[Job]:
    seen: set[tuple[str, str, int]] = set()
    kept = []
    for job in jobs:
        prompt = render_prompt(render_messages(job.planner_input), template)
        key = generation_key("", prompt, job.seed)
        if key not in seen:
            seen.add(key)
            kept.append(job)
    return kept


def full_design(template: str, *, full: bool) -> list[Job]:
    """§10's matrix, one job per distinct key. ``full``: the primary's four families on both
    suites with the placebo arm. Otherwise the second model's: warrant and undefended on dev.
    ``leaked`` shares ``undefended``'s prompts, so it adds no generation (§4)."""
    tasks = [t for t in USER_TASKS if t.id not in PILOT_TASKS]
    suites = ("dev", "holdout") if full else ("dev",)
    pairs = [(t, i) for s in suites for t in tasks for i in injections(s) if i.payload(t)]
    dev_pairs = [(t, i) for t, i in pairs if i in injections("dev")]
    seeds = FULL_SEEDS

    def family(name: str, entries: Iterable[tuple[UserTask, str | None, str | None]]) -> list[Job]:
        code_path = "undefended" if name == "placebo" else name
        inputs = [(t, i, planner_input(t, p, code_path)) for t, i, p in entries]
        jobs = (Job(name, t.id, i, s, pi) for t, i, pi in inputs for s in seeds)
        return _distinct(jobs, template)

    benign: list[tuple[UserTask, str | None, str | None]] = [(t, None, None) for t in tasks]
    attacked = [(t, i.id, i.payload(t)) for t, i in pairs]
    jobs = family("warrant", benign) + family("undefended", benign + attacked)
    if full:
        jobs += family("delimited", benign + attacked)
        jobs += family(
            "placebo", [(t, i.id, placebo_payload(i.payload(t) or "")) for t, i in dev_pairs]
        )
    return jobs


def generate(
    model: Model, pin: ModelPin, jobs: list[Job], out: Path, *, reset: bool = True
) -> None:
    saw = _PROCESS_SAW | {"warrant" for j in jobs if j.family == "warrant"}
    saw |= {"ticket text" for j in jobs if j.planner_input.context}
    if len(saw) > 1:
        raise ValueError("warrant plans are generated in their own process, with no ticket text")
    _PROCESS_SAW.update(saw)
    done = _written_keys(out)
    with out.open("a", encoding="utf-8") as sink:
        for job in jobs:
            prompt = render_prompt(render_messages(job.planner_input), pin.template)
            key = generation_key(pin.sha256, prompt, job.seed)
            if key in done:
                continue
            result = model.generate(prompt, job.seed, reset=reset)
            record = {
                "key": list(key),
                "model": pin.file,
                "seed": job.seed,
                "family": job.family,
                "task": job.task,
                # The first pair with this key: others may share it (§4), so per-injection
                # counts come from the pair being replayed, never from this field.
                "injection": job.injection,
                **result,
            }
            sink.write(json.dumps(record, ensure_ascii=False) + "\n")
            sink.flush()
            os.fsync(sink.fileno())
            done.add(key)


def _written_keys(out: Path) -> set[tuple[str, str, int]]:
    """Keys already written. A job killed mid-write leaves a torn last line: it is no record, so
    it is removed and that key is generated again (§3)."""
    if not out.exists():
        return set()
    text = out.read_text(encoding="utf-8")
    complete, newline, torn = text.rpartition("\n")
    if torn:
        out.write_text(complete + newline, encoding="utf-8")
    keys = set()
    for line in complete.splitlines():
        model_sha, prompt_sha, seed = json.loads(line)["key"]
        keys.add((model_sha, prompt_sha, seed))
    return keys


def available_memory_bytes() -> int:
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024

    class Status(ctypes.Structure):
        _fields_ = (
            ("length", ctypes.c_ulong),
            ("load", ctypes.c_ulong),
            ("total", ctypes.c_ulonglong),
            ("available", ctypes.c_ulonglong),
            ("rest", ctypes.c_ulonglong * 5),
        )

    status = Status()
    status.length = ctypes.sizeof(Status)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # type: ignore[attr-defined]
    return int(status.available)


def refuse_without_memory(available_bytes: int) -> None:
    if available_bytes < MIN_AVAILABLE_BYTES:
        raise MemoryRefused(f"{available_bytes} bytes available, {MIN_AVAILABLE_BYTES} required")


def determinism_check(model: Model, jobs: list[Job], template: str) -> dict[str, Any]:
    """§9: one key generated with and without prefix reuse. Another prompt runs in between, so
    the second generation reuses only the shared prefix, not the whole prompt."""
    prompt = render_prompt(render_messages(jobs[0].planner_input), template)
    other = render_prompt(render_messages(jobs[3].planner_input), template)
    seed = jobs[0].seed
    reset = model.generate(prompt, seed, reset=True)
    model.generate(other, seed, reset=True)
    reused = model.generate(prompt, seed, reset=False)
    reset_again = model.generate(prompt, seed, reset=True)
    return {
        "same_with_reset": reset["output"] == reset_again["output"],
        "same_with_prefix_reuse": reset["output"] == reused["output"],
        "first_token_seconds": {
            "reset": reset["first_token_seconds"],
            "prefix_reuse": reused["first_token_seconds"],
            "reset_again": reset_again["first_token_seconds"],
        },
        "outputs": [reset["output"], reused["output"], reset_again["output"]],
    }


def prompt_lengths(model: Model, template: str) -> dict[str, list[int]]:
    """Tokenized lengths in the full design, one entry per generation. Nothing is generated."""
    found: dict[str, list[int]] = {}
    for job in full_design(template, full=True):
        prompt = render_prompt(render_messages(job.planner_input), template)
        found.setdefault(job.family, []).append(len(model.tokenize(prompt)))
    return found


def _peak_memory_kib() -> int | None:
    status = Path("/proc/self/status")
    if not status.exists():
        return None
    for line in status.read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return None


def pilot(name: str, model_path: Path, out: Path) -> int:
    """Generation and its measurements, with no ticket text anywhere in this process."""
    refuse_without_memory(available_memory_bytes())
    pin = MODELS[name]
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    model = LocalModel(model_path, pin.template)
    jobs = pilot_jobs()
    generate(model, pin, jobs, out / "records.jsonl", reset=True)
    measured = {
        "model": pin.file,
        "system_info": model.system_info(),
        "load_seconds": model.load_seconds,
        "grammar_conversion_seconds": model.grammar_conversion_seconds,
        "grammar_native_overhead_seconds": model.grammar_native_overhead(),
        "determinism": determinism_check(model, jobs, pin.template),
        "run_seconds": time.monotonic() - started,
        "peak_memory_kib": _peak_memory_kib(),
    }
    (out / "measured.json").write_text(json.dumps(measured, indent=1), encoding="utf-8")
    return 0


def lengths(name: str, model_path: Path, out: Path) -> int:
    """§9: the tokenized length of every prompt in the full design. Nothing is generated."""
    refuse_without_memory(available_memory_bytes())
    pin = MODELS[name]
    out.mkdir(parents=True, exist_ok=True)
    found = prompt_lengths(LocalModel(model_path, pin.template), pin.template)
    (out / "prompt_lengths.json").write_text(json.dumps(found), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["pilot", "lengths"])
    parser.add_argument("--model", choices=sorted(MODELS), required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    mode = pilot if args.mode == "pilot" else lengths
    return mode(args.model, args.model_path, args.out)


if __name__ == "__main__":
    sys.exit(main())
