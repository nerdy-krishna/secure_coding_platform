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
