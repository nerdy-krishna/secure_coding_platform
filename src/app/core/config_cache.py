from typing import List

class SystemConfigCache:
    _allowed_origins: List[str] = []
    _is_setup_completed: bool = False

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
