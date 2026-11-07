"""The real-model planner (SPEC_v1.1 §3, §5). Only ``LocalModel`` needs the model and the optional
``llm`` extra, and it imports ``llama_cpp`` when constructed, so ``check`` never needs either.

Generation and scoring both render prompts here, so a generation's key is computed one way. The
chat templates are the models' own, read from the pinned GGUF files and committed byte for byte,
so anyone can re-score the raw records offline; generation checks them against the loaded file
(D-086). The environment matches llama-cpp-python's own chat formatter. It provides no
``strftime_now``: a template path that would put today's date in a prompt raises, so it cannot
vary a key.
"""

import copy
import hashlib
import json
import time
from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Template
from jinja2.sandbox import ImmutableSandboxedEnvironment

from evals.llm_pins import MAX_TOKENS, SAMPLING, SETTINGS
from kernel.plan_lang import plan_json_schema
from kernel.run import PlannerInput

PROMPTS = Path(__file__).resolve().parent / "prompts"
PROMPT_FILE = PROMPTS / "plan_v2.txt"
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
        self.matched: Mapping[str, Any] | None = None  # the record the last plan() used
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
        self.matched = record
        output = str(record["output"])
        if record["stop_reason"] != "stop":
            return output
        try:
            return json.loads(output)
        except (ValueError, RecursionError):
            return output


def decoding_schema() -> dict[str, Any]:
    """§3's one transformation: the pinned converter ignores ``patternProperties``, so a call's
    argument values move to ``additionalProperties``. The grammar stays more permissive than the
    plan language, and the checker still validates argument names."""
    schema = copy.deepcopy(plan_json_schema())
    args = schema["$defs"]["CallStep"]["properties"]["args"]
    ((_, value),) = args.pop("patternProperties").items()
    args["additionalProperties"] = value
    return schema


class LocalModel:
    """One pinned GGUF file under §2's settings. Stops if its chat template is not the committed
    one, because scoring renders prompts from the committed bytes."""

    def __init__(self, path: Path, template: str) -> None:
        from llama_cpp import Llama, LlamaGrammar

        started = time.monotonic()
        self._model = Llama(model_path=str(path), verbose=False, **SETTINGS)
        self.load_seconds = time.monotonic() - started
        if self._model.metadata.get("tokenizer.chat_template") != chat_template_text(template):
            raise ValueError(f"{path} does not carry the committed {template} chat template")
        started = time.monotonic()
        self._grammar = LlamaGrammar.from_json_schema(json.dumps(decoding_schema()), verbose=False)
        self.grammar_conversion_seconds = time.monotonic() - started

    @staticmethod
    def system_info() -> str:
        """What the binary was built with: the evidence that §2's flags took effect."""
        import llama_cpp

        return llama_cpp.llama_print_system_info().decode("utf-8")

    def tokenize(self, prompt: str) -> list[int]:
        """Role markers must become special tokens. No suite text contains ``<|`` (§3), so none
        can form one. Neither pinned file adds a BOS token."""
        return list(self._model.tokenize(prompt.encode("utf-8"), add_bos=False, special=True))

    def grammar_native_overhead(self) -> float:
        """One token with the grammar, less one without: mostly llama.cpp parsing it."""

        def one_token(**grammar: Any) -> float:
            self._model.reset()
            started = time.monotonic()
            self._model.create_completion(self.tokenize("a"), max_tokens=1, seed=1, **grammar)
            return time.monotonic() - started

        return one_token(grammar=self._grammar) - one_token()

    def generate(self, prompt: str, seed: int, *, reset: bool = True) -> dict[str, Any]:
        """One attempt. ``reset`` clears model state first, so nothing is reused from an earlier
        prompt. Without it, llama.cpp reuses the longest shared prefix."""
        from llama_cpp import StoppingCriteriaList

        first_token: list[float] = []

        def timestamps(_tokens: Any, _scores: Any) -> bool:
            if not first_token:
                first_token.append(time.monotonic())
            return False

        if reset:
            self._model.reset()
        started = time.monotonic()
        result: Any = self._model.create_completion(
            self.tokenize(prompt),
            max_tokens=MAX_TOKENS,
            seed=seed,
            grammar=self._grammar,
            stopping_criteria=StoppingCriteriaList([timestamps]),
            **SAMPLING,
        )
        finished = time.monotonic()
        choice = result["choices"][0]
        return {
            "output": choice["text"],
            "stop_reason": choice["finish_reason"],
            "prompt_tokens": result["usage"]["prompt_tokens"],
            "completion_tokens": result["usage"]["completion_tokens"],
            "first_token_seconds": (first_token[0] if first_token else finished) - started,
            "latency_seconds": finished - started,
        }
