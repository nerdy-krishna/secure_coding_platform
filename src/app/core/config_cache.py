import threading
from typing import List, Literal

# Canonical values for the LLM optimization mode. "anthropic_optimized"
# enables prompt caching, tuned prompt variants, and Anthropic-only dispatch.
# "multi_provider" keeps the generic multi-provider behavior.
LLMMode = Literal["anthropic_optimized", "multi_provider"]
LLM_MODE_ANTHROPIC_OPTIMIZED: LLMMode = "anthropic_optimized"
LLM_MODE_MULTI_PROVIDER: LLMMode = "multi_provider"
DEFAULT_LLM_MODE: LLMMode = LLM_MODE_MULTI_PROVIDER


class SystemConfigCache:
    _lock = threading.RLock()
    _allowed_origins: List[str] = []
    _is_setup_completed: bool = False
    _llm_mode: LLMMode = DEFAULT_LLM_MODE

    @classmethod
    def set_allowed_origins(cls, origins: List[str]):
        with cls._lock:
            cls._allowed_origins = origins

    @classmethod
    def get_allowed_origins(cls) -> List[str]:
        with cls._lock:
            return cls._allowed_origins

    @classmethod
    def set_setup_completed(cls, completed: bool):
        with cls._lock:
            cls._is_setup_completed = completed

    @classmethod
    def is_setup_completed(cls) -> bool:
        with cls._lock:
            return cls._is_setup_completed

    _cors_enabled: bool = False

    @classmethod
    def set_cors_enabled(cls, enabled: bool):
        with cls._lock:
            cls._cors_enabled = enabled

    @classmethod
    def is_cors_enabled(cls) -> bool:
        with cls._lock:
            return cls._cors_enabled

    _smtp_config: dict | None = None

    @classmethod
    def set_smtp_config(cls, smtp_config: dict | None):
        with cls._lock:
            cls._smtp_config = smtp_config

    @classmethod
    def get_smtp_config(cls) -> dict | None:
        with cls._lock:
            return cls._smtp_config

    @classmethod
    def set_llm_mode(cls, mode: str) -> None:
        """Set the active LLM optimization mode.

        Raises ValueError for unknown mode values so misconfiguration of this
        security-relevant setting (Anthropic-only dispatch / prompt caching)
        is surfaced immediately rather than silently masked.
        """
        with cls._lock:
            if mode in (LLM_MODE_ANTHROPIC_OPTIMIZED, LLM_MODE_MULTI_PROVIDER):
                cls._llm_mode = mode  # type: ignore[assignment]
            else:
                raise ValueError(
                    f"Unknown LLM mode: {mode!r}; expected one of "
                    f"{{{LLM_MODE_ANTHROPIC_OPTIMIZED!r}, {LLM_MODE_MULTI_PROVIDER!r}}}"
                )

    @classmethod
    def get_llm_mode(cls) -> LLMMode:
        with cls._lock:
            return cls._llm_mode

    @classmethod
    def is_anthropic_optimized(cls) -> bool:
        with cls._lock:
            return cls._llm_mode == LLM_MODE_ANTHROPIC_OPTIMIZED
