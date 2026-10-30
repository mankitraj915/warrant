"""Shared test helpers: build a run environment from a world and run a plan."""

import sqlite3
from collections.abc import Callable
from typing import Any

from domain.payment_mock import PaymentMock
from domain.seed import World, materialize
from kernel.run import Environment, RunResult, run_plan
from planners.fuzz import raw_extractor


def run_world(
    plan: dict[str, Any],
    world: World,
    extractor: Callable[[str], list[object]] = raw_extractor,
    run_id: str = "test-run",
) -> tuple[RunResult, PaymentMock, sqlite3.Connection]:
    """Run ``plan`` on a fresh database of ``world``; also return a pristine copy."""
    r, env, pristine = run_world_env(plan, world, extractor, run_id)
    assert isinstance(env.provider, PaymentMock)
    return r, env.provider, pristine


def run_world_env(
    plan: dict[str, Any],
    world: World,
    extractor: Callable[[str], list[object]] = raw_extractor,
    run_id: str = "test-run",
) -> tuple[RunResult, Environment, sqlite3.Connection]:
    """As ``run_world``, returning the environment (provider and database)."""
    env = Environment(db=materialize(world), provider=PaymentMock(), extractor=extractor)
    return run_plan(plan, env, run_id=run_id), env, materialize(world)
