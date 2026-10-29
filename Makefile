# Thin wrapper: every recipe lives in scripts/tasks.py so it behaves the same on
# Windows and POSIX. Without make, run `uv run --locked python scripts/tasks.py <target>`.
RUN := uv run --locked python scripts/tasks.py

.PHONY: check lint typecheck test

check lint typecheck test:
	$(RUN) $@
