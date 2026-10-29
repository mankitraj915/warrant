"""kernel/ must not import planners/, evals/ or quarantine/ (SPEC §4.1).

Two checks:
- Static (AST): forbidden imports, plus the dynamic-import and code-execution
  forms that would bypass a static check (importlib, __import__, exec, eval,
  compile, builtins, sys.modules, pkgutil, runpy, pydantic.ImportString).
  Python cannot be fully checked statically, so this guards against mistakes,
  not a hostile author (the attacker does not control kernel code).
- Runtime: import every kernel module in a fresh interpreter whose import
  system refuses the forbidden packages, then assert none got loaded.
"""

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "kernel"
FORBIDDEN_PACKAGES = frozenset({"planners", "evals", "quarantine"})
FORBIDDEN_DYNAMIC = frozenset({"importlib", "builtins", "pkgutil", "runpy"})
FORBIDDEN_NAMES = frozenset({"__import__", "__builtins__", "exec", "eval", "compile"})
FORBIDDEN_ATTRIBUTES = frozenset({"__import__", "modules"})
FORBIDDEN_FROM_NAMES = frozenset({"ImportString"})


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
            found += [
                f"line {node.lineno}: imports {a.name}"
                for a in node.names
                if a.name in FORBIDDEN_FROM_NAMES
            ]
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            found.append(f"line {node.lineno}: dynamic import or exec via {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES:
            found.append(f"line {node.lineno}: dynamic import via .{node.attr}")
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


_RUNTIME_PROBE = """
import importlib, sys
FORBIDDEN = set(sys.argv[1].split(","))

class Refuse:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in FORBIDDEN:
            raise ImportError("kernel imported forbidden package " + name)
        return None

sys.meta_path.insert(0, Refuse())
for module in sys.argv[2:]:
    importlib.import_module(module)
loaded = sorted(m for m in sys.modules if m.split(".")[0] in FORBIDDEN)
assert not loaded, loaded
"""


def test_kernel_modules_load_without_untrusted_packages() -> None:
    modules = [_module_name(path) for path in sorted(KERNEL.rglob("*.py"))]
    result = subprocess.run(
        [sys.executable, "-c", _RUNTIME_PROBE, ",".join(sorted(FORBIDDEN_PACKAGES)), *modules],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


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
        "import builtins\nbuiltins.__import__('planners')": "kernel.policy",
        "exec('import planners')": "kernel.policy",
        "eval('1')": "kernel.policy",
        "compile('import planners', 'f', 'exec')": "kernel.policy",
        "import sys\nsys.modules['planners']": "kernel.policy",
        "import pkgutil": "kernel.policy",
        "import runpy": "kernel.policy",
        "from pydantic import ImportString": "kernel.policy",
        "getattr(__builtins__, '__imp' + 'ort__')('planners')": "kernel.policy",
    }
    for source, module in cases.items():
        assert boundary_violations(source, module), source


def test_scanner_allows_kernel_internal_imports() -> None:
    for source in ("from . import labels", "from .labels import Label", "import kernel.labels"):
        assert boundary_violations(source, "kernel.policy") == [], source
