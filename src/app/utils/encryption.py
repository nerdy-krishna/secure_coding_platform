# src/app/utils/encryption.py

from cryptography.fernet import Fernet
from app.core.config import settings


class FernetEncrypt:
    """
    A utility class for encrypting and decrypting data using Fernet.
    It automatically handles missing base64 padding in the key from the .env file.
    """

    _key_str = settings.ENCRYPTION_KEY
    if not _key_str:
        raise ValueError(
            "ENCRYPTION_KEY environment variable not set. Please generate a new one."
        )

    try:
        # Some systems or .env parsers strip '=' padding. We re-add it here.
        # A valid base64 string's length must be a multiple of 4.
        padded_key_str = _key_str + "=" * (-len(_key_str) % 4)

        # The Fernet constructor expects the base64-encoded key as bytes.
        key_as_bytes = padded_key_str.encode("utf-8")

        # The Fernet constructor performs the base64 decoding internally.
        # It will raise a ValueError here if the key is still invalid after padding.
        _fernet = Fernet(key_as_bytes)

    except Exception as e:
        raise ValueError(
            "Invalid ENCRYPTION_KEY. Could not initialize encryption service. "
            f"Please ensure it's a valid, URL-safe base64-encoded key. Original error: {e}"
        ) from e

    @classmethod
    def encrypt(cls, data: str) -> str:
        """Encrypts a string and returns the encrypted data as a string."""
        return cls._fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    @classmethod
    def decrypt(cls, encrypted_data: str) -> str:
        """Decrypts an encrypted string and returns the original data."""
        return cls._fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8")
