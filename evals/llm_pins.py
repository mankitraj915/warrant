"""What SPEC_v1.1 §1, §2 and §9 fix: models, runtime settings, sampling, pilot design.

``tests/test_llm_generate.py`` compares these with the spec's text. Changing one is a deviation.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPin:
    template: str
    repository: str
    commit: str
    file: str
    size: int
    sha256: str

    @property
    def url(self) -> str:
        return f"https://huggingface.co/{self.repository}/resolve/{self.commit}/{self.file}"


MODELS = {
    "granite": ModelPin(
        template="granite",
        repository="ibm-granite/granite-3.3-2b-instruct-GGUF",
        commit="7cdf86ccd1f1bb3491c9b7017b033f2e51367397",
        file="granite-3.3-2b-instruct-Q4_K_M.gguf",
        size=1_545_303_328,
        sha256="ac71e9e32c0bea919b409c5918f69ca74339854b0319c5065e4e9fb6d95c4852",
    ),
    "qwen": ModelPin(
        template="qwen",
        repository="Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        commit="91cad51170dc346986eccefdc2dd33a9da36ead9",
        file="qwen2.5-1.5b-instruct-q4_k_m.gguf",
        size=1_117_320_736,
        sha256="6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e",
    ),
}
SETTINGS = {"n_ctx": 4096, "n_threads": 4, "n_batch": 512, "n_gpu_layers": 0}
MAX_TOKENS = 1024
SAMPLING = {"temperature": 0.2, "top_k": 40, "top_p": 0.95, "min_p": 0.0, "repeat_penalty": 1.0}
MIN_AVAILABLE_BYTES = 3_000_000_000

PILOT_TASKS = ("T01", "T02", "T04", "T11", "T23")
PILOT_SEEDS = (11101, 11102, 11103)  # the repeat's go/no-go (§9, D-090)
PILOT_COMPARISON_SEEDS = (11001, 11002, 11003)  # the first pilot's: compared, never decisive
FULL_SEEDS = (21001, 21002, 21003)
