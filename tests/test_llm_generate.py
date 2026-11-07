"""The pilot's generator and report, with a fake model: no model ever runs in ``check``
(SPEC_v1.1 §2, §3, §5, §9). The real thing runs only on Actions."""

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import evals.llm_generate
import evals.llm_pilot
from evals.llm_generate import (
    Job,
    MemoryRefused,
    full_design,
    generate,
    pilot_jobs,
    refuse_without_memory,
)
from evals.llm_pilot import capacity, go_no_go, main, percentile, score_pilot
from evals.llm_pins import MAX_TOKENS, MODELS, PILOT_SEEDS, PILOT_TASKS, SAMPLING, SETTINGS
from evals.llm_score import run_instance
from evals.tasks.dev import USER_TASKS
from kernel.plan_lang import plan_json_schema
from planners.llm_local import ReplayPlanner, decoding_schema

ROOT = Path(__file__).resolve().parent.parent
SPEC = (ROOT / "docs" / "SPEC_v1.1.md").read_text(encoding="utf-8")
TASKS = {t.id: t for t in USER_TASKS}


class FakeModel:
    """Writes each task's oracle plan, found by the request in the prompt."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, bool]] = []

    def tokenize(self, prompt: str) -> list[int]:
        return list(range(len(prompt.split())))

    def generate(self, prompt: str, seed: int, *, reset: bool = True) -> dict[str, Any]:
        self.calls.append((prompt, seed, reset))
        task = next(t for t in USER_TASKS if f"Request: {t.prompt}" in prompt)
        return {
            "output": json.dumps(task.oracle),
            "stop_reason": "stop",
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "first_token_seconds": 1.0,
            "latency_seconds": 6.0,
        }


@pytest.fixture(autouse=True)
def _a_fresh_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """§5's refusal is per process, and each test stands for one."""
    monkeypatch.setattr(evals.llm_generate, "_PROCESS_SAW", set(), raising=False)


def _written(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ---- The pins are the spec's. -----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(MODELS))
def test_each_model_pin_is_the_registered_one(name: str) -> None:
    pin = MODELS[name]
    for value in (pin.repository, pin.commit, pin.file, pin.sha256, f"{pin.size:,}"):
        assert value in SPEC, value
    assert pin.url == f"https://huggingface.co/{pin.repository}/resolve/{pin.commit}/{pin.file}"


def test_the_runtime_settings_are_the_registered_ones() -> None:
    for name, value in {**SETTINGS, "max_tokens": MAX_TOKENS, **SAMPLING}.items():
        spec_name = "temperature" if name == "temperature" else name
        assert re.search(rf"`{spec_name}={re.escape(str(value))}`", SPEC), name


def test_the_pilot_design_is_the_registered_one() -> None:
    assert PILOT_TASKS == ("T01", "T02", "T04", "T11", "T23")
    assert PILOT_SEEDS == (11101, 11102, 11103)
    assert "decision 11101, 11102, 11103; comparison 11001, 11002, 11003" in SPEC


def test_the_extra_pins_the_package_and_the_lock_pins_the_sdist() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"llama-cpp-python==0.3.36"' in pyproject
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    sha = "832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e"
    assert sha in SPEC
    assert f"sha256:{sha}" in lock


def test_the_workflow_builds_with_the_registered_flags_and_verifies_the_model() -> None:
    workflow = (ROOT / ".github" / "workflows" / "llm-run.yml").read_text(encoding="utf-8")
    for flag in ("-DGGML_NATIVE=OFF", "-DGGML_AVX2=ON", "-DGGML_FMA=ON", "-DGGML_F16C=ON"):
        assert flag in workflow
        assert flag in SPEC
    assert "sha256sum" in workflow
    assert "workflow_dispatch" in workflow
    assert "--extra llm" in workflow


# ---- The decoding schema. ---------------------------------------------------------------


def test_the_decoding_schema_makes_only_the_registered_change() -> None:
    original = plan_json_schema()
    decoding = decoding_schema()
    before = original["$defs"]["CallStep"]["properties"]["args"]
    after = decoding["$defs"]["CallStep"]["properties"]["args"]
    assert "patternProperties" in before
    assert "patternProperties" not in after
    value = next(iter(before["patternProperties"].values()))
    assert after["additionalProperties"] == value
    decoding["$defs"]["CallStep"]["properties"]["args"] = before
    assert decoding == original


def test_the_decoding_schema_leaves_the_kernels_schema_alone() -> None:
    decoding_schema()
    assert "patternProperties" in plan_json_schema()["$defs"]["CallStep"]["properties"]["args"]


# ---- Generation. ------------------------------------------------------------------------


def test_the_pilot_has_fifteen_generations_with_no_ticket_text() -> None:
    jobs = pilot_jobs()
    assert len(jobs) == 15
    assert {j.family for j in jobs} == {"warrant"}
    assert {j.task for j in jobs} == set(PILOT_TASKS)
    assert {j.seed for j in jobs} == set(PILOT_SEEDS)
    assert all(not j.planner_input.context for j in jobs)


def test_records_hold_what_the_spec_names_and_replay_through_the_kernel(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    model = FakeModel()
    generate(model, MODELS["granite"], pilot_jobs(), out)
    records = _written(out)
    assert len(records) == 15
    for field in (
        "key",
        "model",
        "seed",
        "family",
        "task",
        "injection",
        "output",
        "prompt_tokens",
        "completion_tokens",
        "stop_reason",
        "latency_seconds",
        "first_token_seconds",
    ):
        assert field in records[0], field
    task = TASKS["T01"]
    replay = ReplayPlanner(MODELS["granite"].sha256, "granite", PILOT_SEEDS[0], records)
    instance = run_instance(task, None, "warrant", replay, "replayed")
    assert instance.raw_plan == task.oracle


def test_generation_resumes_and_a_written_record_is_final(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    jobs = pilot_jobs()
    first = FakeModel()
    generate(first, MODELS["granite"], jobs[:4], out)
    before = _written(out)
    second = FakeModel()
    generate(second, MODELS["granite"], jobs, out)
    assert _written(out)[:4] == before
    assert len(_written(out)) == 15
    assert len(second.calls) == 11


def test_equal_keys_share_one_record(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    job = pilot_jobs()[0]
    model = FakeModel()
    generate(model, MODELS["granite"], [job, job], out)
    assert len(model.calls) == 1


def test_a_warrant_generation_process_refuses_any_job_carrying_ticket_text(tmp_path: Path) -> None:
    """§5: a process that generates a warrant plan has never been given ticket text."""
    task = TASKS["T01"]
    leaked = _input_of(task, "leaked")
    jobs = [*pilot_jobs()[:1], Job("undefended", task.id, None, 11001, leaked)]
    model = FakeModel()
    with pytest.raises(ValueError, match="own process"):
        generate(model, MODELS["granite"], jobs, tmp_path / "records.jsonl")
    assert not model.calls, "the check must run before any generation"


def _input_of(task: Any, family: str) -> Any:
    class Recording:
        seen: Any = None

        def plan(self, planner_input: Any) -> Any:
            Recording.seen = planner_input
            return {}

    run_instance(task, "injected", family, Recording(), "seen")
    return Recording.seen


def test_each_generation_resets_model_state_by_default(tmp_path: Path) -> None:
    model = FakeModel()
    generate(model, MODELS["granite"], pilot_jobs()[:2], tmp_path / "r.jsonl")
    assert [reset for _, _, reset in model.calls] == [True, True]


def test_a_start_below_three_gb_is_refused() -> None:
    with pytest.raises(MemoryRefused):
        refuse_without_memory(available_bytes=2_999_999_999)
    refuse_without_memory(available_bytes=3_000_000_000)


# ---- The full design's size. ------------------------------------------------------------


def _generations(jobs: list[Job]) -> Counter[str]:
    return Counter(j.family for j in jobs)


def test_the_full_design_counts_are_the_registered_ones_except_shared_placebo_keys() -> None:
    """§10's table counts the placebo arm by instance, 1,086. Different injections on one task can
    have the same numbers, and equal keys share a record (§4), so it needs 924 generations."""
    jobs = full_design("granite", full=True)
    counts = _generations(jobs)
    assert counts == {"warrant": 105, "undefended": 2475, "delimited": 2475, "placebo": 924}
    assert sum(counts.values()) == 5979
    assert {j.seed for j in jobs} == {21001, 21002, 21003}
    assert not {j.task for j in jobs} & set(PILOT_TASKS)


def test_the_second_models_design_is_the_registered_one() -> None:
    counts = _generations(full_design("qwen", full=False))
    assert counts == {"warrant": 105, "undefended": 1191}


# ---- The report. ------------------------------------------------------------------------


def test_percentile_is_nearest_rank() -> None:
    values = [float(n) for n in range(1, 101)]
    assert percentile(values, 95) == 95.0
    assert percentile([3.0], 95) == 3.0


def test_capacity_estimates_from_prompt_and_completion_cost() -> None:
    result = capacity(
        prompt_lengths=[100, 200],
        seconds_per_prompt_token=0.1,
        seconds_per_completion_token=0.5,
        completion_tokens=10,
    )
    assert result["total_seconds"] == pytest.approx(30 + 10)
    assert result["jobs"] == 1
    assert result["passes"]


def test_capacity_fails_past_the_job_limit() -> None:
    result = capacity(
        prompt_lengths=[1000] * 10_000,
        seconds_per_prompt_token=1.0,
        seconds_per_completion_token=0.0,
        completion_tokens=0,
    )
    assert result["jobs"] > 256
    assert not result["passes"]


def test_capacity_fails_past_seven_days_of_wall_clock() -> None:
    result = capacity(
        prompt_lengths=[1000] * 3_000,
        seconds_per_prompt_token=1.0,
        seconds_per_completion_token=0.0,
        completion_tokens=0,
        concurrency=1,
    )
    assert result["jobs"] <= 256
    assert result["wall_days"] > 7
    assert not result["passes"]


@pytest.mark.parametrize(
    ("valid", "correct", "fits", "expected"),
    [
        (8, 3, True, True),
        (7, 15, True, False),
        (15, 2, True, False),
        (15, 15, False, False),
    ],
)
def test_the_go_rule_is_the_registered_threshold(
    valid: int, correct: int, fits: bool, expected: bool
) -> None:
    assert go_no_go(valid=valid, correct=correct, capacity_passes=fits) is expected
    assert "valid plans ≥ 8/15" in SPEC
    assert "correct plans ≥ 3/15" in SPEC


def test_the_pilot_score_counts_a_correct_model_and_passes_the_oracles(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    score = score_pilot(MODELS["granite"], _written(out))
    assert score["valid"] == 15
    assert score["correct"] == 15
    assert score["truncated"] == 0
    assert score["stops"] == []


def test_the_pilot_score_counts_failures_without_retrying(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    records = _written(out)
    records[0]["output"] = "{not json"
    records[1]["stop_reason"] = "length"
    records[2]["output"] = '{"version": 1, "steps": [{"call": "no_such_tool", "args": {}}]}'
    score = score_pilot(MODELS["granite"], records)
    assert score["valid"] == 12
    assert score["correct"] == 12
    assert score["truncated"] == 1
    assert score["rejected"] == 2


def test_a_missing_generation_stops_the_score(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    with pytest.raises(Exception, match="no generation"):
        score_pilot(MODELS["granite"], _written(out)[:-1])


# ---- The Gate B review's findings (docs/reviews/V1_1_GATE_B_REVIEW.md). -------------------


def test_m2_the_score_judges_the_record_the_replay_matched(tmp_path: Path) -> None:
    """A record with the same task and seed but another prompt must not be scored."""
    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    keyed = _written(out)
    stale = [{**r, "key": [r["key"][0], f"{i:064d}", r["key"][2]]} for i, r in enumerate(keyed)]
    bad = [{**r, "output": "not json"} for r in keyed]
    score = score_pilot(MODELS["granite"], stale + bad)
    assert score["outcomes"] == {"rejected": 15}
    assert score["valid"] == 0
    assert score["correct"] == 0


def test_m5_the_score_says_how_many_valid_plans_could_test_the_oracles(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    score = score_pilot(MODELS["granite"], _written(out))
    assert score["valid_reading_untrusted"] == 3, "only T11's oracle reads untrusted text"
    assert score["distinct_valid_plans"] == 5
    assert score["oracle_runs"] > 0


def test_m7_one_process_cannot_generate_warrant_plans_after_ticket_text(tmp_path: Path) -> None:
    task = TASKS["T01"]
    text_job = Job("undefended", task.id, None, 11001, _input_of(task, "leaked"))
    model = FakeModel()
    generate(model, MODELS["granite"], [text_job], tmp_path / "text.jsonl")
    with pytest.raises(ValueError, match="own process"):
        generate(model, MODELS["granite"], pilot_jobs()[:1], tmp_path / "warrant.jsonl")
    assert len(model.calls) == 1


def test_m7_the_prompt_lengths_run_as_their_own_mode() -> None:
    workflow = (ROOT / ".github" / "workflows" / "llm-run.yml").read_text(encoding="utf-8")
    assert "evals.llm_generate lengths" in workflow
    assert "evals.llm_generate pilot" in workflow


def test_l3_a_stop_is_never_a_go_and_fails_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert go_no_go(valid=15, correct=15, capacity_passes=True, stop=True) is False
    monkeypatch.setattr("evals.llm_pilot.report", lambda pin, raw: {"stop": True, "go": False})
    assert main(["--model", "granite", "--raw", str(tmp_path)]) != 0


def test_l7_a_torn_last_line_is_dropped_and_generation_resumes(tmp_path: Path) -> None:
    out = tmp_path / "records.jsonl"
    jobs = pilot_jobs()
    generate(FakeModel(), MODELS["granite"], jobs[:2], out)
    whole = out.read_text(encoding="utf-8")
    out.write_text(whole + '{"key": ["torn', encoding="utf-8")
    generate(FakeModel(), MODELS["granite"], jobs[:3], out)
    records = _written(out)
    assert len(records) == 3


# ---- The repeat: fresh seeds decide, the first pilot's seeds only compare (§9, D-090). ------


def _raw(tmp_path: Path, *, decision: str | None = None, comparison: str | None = None) -> Path:
    """A pilot artifact from the fake model, with one seed set's outputs replaced if asked."""
    from evals.llm_pins import PILOT_COMPARISON_SEEDS

    out = tmp_path / "records.jsonl"
    generate(FakeModel(), MODELS["granite"], pilot_jobs(), out)
    generate(FakeModel(), MODELS["granite"], pilot_jobs(PILOT_COMPARISON_SEEDS), out)
    records = _written(out)
    for record in records:
        if record["seed"] in PILOT_SEEDS and decision is not None:
            record["output"] = decision
        if record["seed"] in PILOT_COMPARISON_SEEDS and comparison is not None:
            record["output"] = comparison
    out.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    (tmp_path / "measured.json").write_text('{"load_seconds": 1.0}', encoding="utf-8")
    (tmp_path / "prompt_lengths.json").write_text('{"warrant": [100]}', encoding="utf-8")
    (tmp_path / "build_seconds.txt").write_text("1\n", encoding="utf-8")
    return tmp_path


def test_the_comparison_seeds_cannot_turn_a_no_go_into_a_go(tmp_path: Path) -> None:
    from evals.llm_pilot import report

    result = report(MODELS["granite"], _raw(tmp_path, decision="not json"))
    assert result["score"]["valid"] == 0
    assert result["comparison_seeds"]["valid"] == 15
    assert result["go"] is False


def test_the_comparison_seeds_cannot_turn_a_go_into_a_no_go(tmp_path: Path) -> None:
    from evals.llm_pilot import report

    result = report(MODELS["granite"], _raw(tmp_path, comparison="not json"))
    assert result["score"]["valid"] == 15
    assert result["comparison_seeds"]["valid"] == 0
    assert result["go"] is True


def test_an_oracle_failure_on_a_comparison_seed_is_still_a_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evals import llm_pilot
    from evals.llm_pins import PILOT_COMPARISON_SEEDS

    real = llm_pilot.score_pilot

    def failing(pin: Any, records: Any, seeds: Any = PILOT_SEEDS) -> dict[str, Any]:
        score = real(pin, records, seeds)
        return {**score, "stops": ["NI-1"]} if seeds == PILOT_COMPARISON_SEEDS else score

    monkeypatch.setattr(llm_pilot, "score_pilot", failing)
    result = llm_pilot.report(MODELS["granite"], _raw(tmp_path))
    assert result["stop"] is True
    assert result["go"] is False


def test_the_capacity_estimate_comes_from_the_decision_seeds(tmp_path: Path) -> None:
    from evals.llm_pilot import report
    from evals.llm_pins import PILOT_COMPARISON_SEEDS

    raw = _raw(tmp_path)
    records = _written(raw / "records.jsonl")
    for record in records:
        if record["seed"] in PILOT_COMPARISON_SEEDS:
            record["completion_tokens"] = 999
    (raw / "records.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )
    assert report(MODELS["granite"], raw)["costs"]["completion_tokens_p95"] == 50


def test_the_pilot_job_generates_both_seed_sets_and_checks_determinism_on_the_decision_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evals.llm_pins import PILOT_COMPARISON_SEEDS

    class Loaded(FakeModel):
        load_seconds = 1.0
        grammar_conversion_seconds = 0.0

        def __init__(self, _path: Path, _template: str) -> None:
            super().__init__()

        @staticmethod
        def system_info() -> str:
            return ""

        def grammar_native_overhead(self) -> float:
            return 0.0

    monkeypatch.setattr(evals.llm_generate, "LocalModel", Loaded)
    monkeypatch.setattr(evals.llm_generate, "available_memory_bytes", lambda: 10**10)
    assert evals.llm_generate.pilot("granite", tmp_path / "model", tmp_path) == 0
    records = _written(tmp_path / "records.jsonl")
    assert len(records) == 30
    assert {r["seed"] for r in records} == {*PILOT_SEEDS, *PILOT_COMPARISON_SEEDS}
    measured = json.loads((tmp_path / "measured.json").read_text(encoding="utf-8"))
    assert measured["determinism"]["same_with_reset"] is True


# ---- The Gate B re-review (docs/reviews/V1_1_GATE_B_REREVIEW.md). -------------------------


@pytest.mark.harness_gap("oracle failures are not stops")
def test_rereview_m4_a_real_oracle_failure_reaches_the_stop_and_the_go(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is stubbed between ``ni_oracles`` and the report's answer."""
    monkeypatch.setattr(
        "evals.llm_pilot.ni_oracles", lambda *_args, **_kwargs: [("NI-1", "broken")]
    )
    result = evals.llm_pilot.report(MODELS["granite"], _raw(tmp_path))
    assert result["score"]["stops"]
    assert result["stop"] is True
    assert result["go"] is False


@pytest.mark.parametrize("character", ["\u2028", "\u0085"])
def test_rereview_m1_a_line_separator_in_an_output_leaves_the_records_readable(
    tmp_path: Path, character: str
) -> None:
    class Separating(FakeModel):
        def generate(self, prompt: str, seed: int, *, reset: bool = True) -> dict[str, Any]:
            return {**super().generate(prompt, seed, reset=reset), "output": f"a{character}b"}

    raw = _raw(tmp_path)
    out = raw / "records.jsonl"
    out.unlink()
    jobs = [*pilot_jobs(), *pilot_jobs((11001, 11002, 11003))]
    generate(Separating(), MODELS["granite"], jobs[:2], out)
    generate(Separating(), MODELS["granite"], jobs, out)
    result = evals.llm_pilot.report(MODELS["granite"], raw)
    assert result["score"]["rejected"] == 15
    assert out.read_text(encoding="utf-8").count("\n") == 30


def test_capacity_counts_each_jobs_load_and_build_time() -> None:
    plain = capacity(
        prompt_lengths=[1000] * 18,
        seconds_per_prompt_token=1.0,
        seconds_per_completion_token=0.0,
        completion_tokens=0,
    )
    assert plain["jobs"] == 1
    loaded = capacity(
        prompt_lengths=[1000] * 18,
        seconds_per_prompt_token=1.0,
        seconds_per_completion_token=0.0,
        completion_tokens=0,
        job_overhead_seconds=600,
    )
    assert loaded["jobs"] == 2
