"""The real-model planner's text side, which needs no model (SPEC_v1.1 §3, §5).

Generation and scoring both render prompts here, so a generation's key is computed one way. The
chat templates are the models' own, read from the pinned GGUF files and committed byte for byte,
so anyone can re-score the raw records offline; generation checks them against the loaded file
(D-086). The environment matches llama-cpp-python's own chat formatter. It provides no
``strftime_now``: a template path that would put today's date in a prompt raises, so it cannot
vary a key.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Template
from jinja2.sandbox import ImmutableSandboxedEnvironment

from kernel.run import PlannerInput

PROMPTS = Path(__file__).resolve().parent / "prompts"
PROMPT_FILE = PROMPTS / "plan_v1.txt"
CHAT_TEMPLATES = {
    "granite": "granite-3.3-2b-instruct.jinja",
    "qwen": "qwen2.5-1.5b-instruct.jinja",
}
CHAT_TEMPLATE_SHA256 = {
    "granite": "8a58e18acd9ca00a43a285fe6ba3760efbda06b5ab7fb57875bfacd72957ed5e",
    "qwen": "d5495a1e5db0611132a97e46a65dbb64a642a499421228b9c8b93229097fa9a4",
}
_ENVIRONMENT = ImmutableSandboxedEnvironment(
    loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True
)

Message = dict[str, str]
Key = tuple[str, str, int]


class MissingGeneration(Exception):
    """No record for this input. A hard failure: scoring never falls back to anything (§5)."""


def chat_template_text(template: str) -> str:
    return (PROMPTS / "chat_templates" / CHAT_TEMPLATES[template]).read_bytes().decode("utf-8")


@cache
def _compiled(template: str) -> Template:
    return _ENVIRONMENT.from_string(chat_template_text(template))


@cache
def _system_text() -> str:
    return PROMPT_FILE.read_bytes().decode("utf-8")


def render_messages(planner_input: PlannerInput) -> list[Message]:
    """§3: the fixed prompt as the system message, the request and any context as the user's."""
    system = _system_text().replace("@@SIGNATURES@@", planner_input.tool_signatures)
    user = f"Request: {planner_input.request}"
    if planner_input.context:
        texts = "\n\n".join(text for text, _ in planner_input.context)
        user = f"{user}\n\nTicket text:\n{texts}"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def render_prompt(messages: list[Message], template: str) -> str:
    return _compiled(template).render(messages=messages, add_generation_prompt=True)


def generation_key(model_sha256: str, prompt: str, seed: int) -> Key:
    """§4: equal keys share one record."""
    return (model_sha256, hashlib.sha256(prompt.encode("utf-8")).hexdigest(), seed)


class ReplayPlanner:
    """Returns the stored output for the input the kernel built, or fails.

    Any output that is not a complete JSON document, including one cut off at ``max_tokens`` even
    if it happens to parse, is returned as text, which the parser rejects: a failed task (§3).
    """

    def __init__(
        self, model_sha256: str, template: str, seed: int, records: Iterable[Mapping[str, Any]]
    ) -> None:
        self._model = model_sha256
        self._template = template
        self._seed = seed
        self._records: dict[Key, Mapping[str, Any]] = {}
        for record in records:
            model, prompt, record_seed = record["key"]
            key = (str(model), str(prompt), int(record_seed))
            if key in self._records:
                raise ValueError(f"duplicate record for {key}: a written record is final")
            self._records[key] = record

    def plan(self, planner_input: PlannerInput) -> Any:
        prompt = render_prompt(render_messages(planner_input), self._template)
        key = generation_key(self._model, prompt, self._seed)
        record = self._records.get(key)
        if record is None:
            raise MissingGeneration(f"no generation for {key}")
        output = str(record["output"])
        if record["stop_reason"] != "stop":
            return output
        try:
            return json.loads(output)
        except (ValueError, RecursionError):
            return output
