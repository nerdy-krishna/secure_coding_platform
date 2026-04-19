from typing import List, Literal

# Canonical values for the LLM optimization mode. "anthropic_optimized"
# enables prompt caching, tuned prompt variants, and Anthropic-only dispatch.
# "multi_provider" keeps the generic multi-provider behavior.
LLMMode = Literal["anthropic_optimized", "multi_provider"]
LLM_MODE_ANTHROPIC_OPTIMIZED: LLMMode = "anthropic_optimized"
LLM_MODE_MULTI_PROVIDER: LLMMode = "multi_provider"
DEFAULT_LLM_MODE: LLMMode = LLM_MODE_MULTI_PROVIDER


class SystemConfigCache:
    _allowed_origins: List[str] = []
    _is_setup_completed: bool = False
    _llm_mode: LLMMode = DEFAULT_LLM_MODE

    @classmethod
    def set_allowed_origins(cls, origins: List[str]):
        cls._allowed_origins = origins

    @classmethod
    def get_allowed_origins(cls) -> List[str]:
        return cls._allowed_origins

    @classmethod
    def set_setup_completed(cls, completed: bool):
        cls._is_setup_completed = completed

    @classmethod
    def is_setup_completed(cls) -> bool:
        return cls._is_setup_completed

    _cors_enabled: bool = False

    @classmethod
    def set_cors_enabled(cls, enabled: bool):
        cls._cors_enabled = enabled

    @classmethod
    def is_cors_enabled(cls) -> bool:
        return cls._cors_enabled

    _smtp_config: dict | None = None

    @classmethod
    def set_smtp_config(cls, smtp_config: dict | None):
        cls._smtp_config = smtp_config

    @classmethod
    def get_smtp_config(cls) -> dict | None:
        return cls._smtp_config

    @classmethod
    def set_llm_mode(cls, mode: str) -> None:
        """Set the active LLM optimization mode.

        Unknown values silently fall back to the multi-provider default so a
        corrupt DB row can't lock the app into an unusable state.
        """
        if mode in (LLM_MODE_ANTHROPIC_OPTIMIZED, LLM_MODE_MULTI_PROVIDER):
            cls._llm_mode = mode  # type: ignore[assignment]
        else:
            cls._llm_mode = DEFAULT_LLM_MODE

    @classmethod
    def get_llm_mode(cls) -> LLMMode:
        return cls._llm_mode

    @classmethod
    def is_anthropic_optimized(cls) -> bool:
        return cls._llm_mode == LLM_MODE_ANTHROPIC_OPTIMIZED
