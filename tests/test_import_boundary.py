"""kernel/ must not import planners/, evals/ or quarantine/ (SPEC §4.1).

The check is static (AST), so it also forbids dynamic imports inside the kernel;
otherwise ``importlib.import_module("planners")`` would bypass it.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "kernel"
FORBIDDEN_PACKAGES = frozenset({"planners", "evals", "quarantine"})
FORBIDDEN_DYNAMIC = frozenset({"importlib", "__import__"})


def _module_name(path: Path) -> str:
    parts = path.relative_to(ROOT).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _resolve(module: str | None, level: int, current: str, is_package: bool) -> str:
    if level == 0:
        return module or ""
    package = current.split(".") if is_package else current.split(".")[:-1]
    base = package[: len(package) - (level - 1)]
    return ".".join([*base, module] if module else base)


def boundary_violations(source: str, current: str, is_package: bool = False) -> list[str]:
    """Return a description of every forbidden import in ``source``."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        targets: list[str] = []
        if isinstance(node, ast.Import):
            targets = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = _resolve(node.module, node.level, current, is_package)
            targets = [base, *(".".join(filter(None, (base, a.name))) for a in node.names)]
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_DYNAMIC:
            found.append(f"line {node.lineno}: dynamic import via {node.id}")
        for target in targets:
            top = target.split(".")[0]
            if top in FORBIDDEN_PACKAGES or top in FORBIDDEN_DYNAMIC:
                found.append(f"line {node.lineno}: imports {target}")
    return found


def test_kernel_does_not_import_untrusted_packages() -> None:
    files = sorted(KERNEL.rglob("*.py"))
    assert files, "kernel/ has no Python files; the boundary check would be vacuous"
    violations = [
        f"{path.relative_to(ROOT)} {v}"
        for path in files
        for v in boundary_violations(
            path.read_text(encoding="utf-8"), _module_name(path), path.name == "__init__.py"
        )
    ]
    assert violations == []


def test_scanner_detects_each_forbidden_form() -> None:
    cases = {
        "import planners": "kernel.policy",
        "import evals.harness as h": "kernel.policy",
        "from quarantine import extractor": "kernel.policy",
        "from quarantine.extractor import extract": "kernel.policy",
        "from ..planners import oracle": "kernel.policy",
        "from .. import evals": "kernel.policy",
        "import importlib": "kernel.policy",
        "x = __import__('planners')": "kernel.policy",
    }
    for source, module in cases.items():
        assert boundary_violations(source, module), source


def test_scanner_allows_kernel_internal_imports() -> None:
    for source in ("from . import labels", "from .labels import Label", "import kernel.labels"):
        assert boundary_violations(source, "kernel.policy") == [], source
