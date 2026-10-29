# Convenience alias only. The canonical interface is
#   uv run --locked python scripts/tasks.py <target>
# and every recipe lives there, so it behaves the same on Windows and POSIX.
RUN := uv run --locked python scripts/tasks.py

.PHONY: check lint typecheck test fuzz eval

check lint typecheck test fuzz eval:
	$(RUN) $@
