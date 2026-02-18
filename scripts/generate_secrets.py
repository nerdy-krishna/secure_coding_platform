import secrets
import base64
import os
import sys

def generate_fernet_key():
    """Generates a base64-encoded 32-byte key compatible with Fernet."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

def generate_secret(length=50):
    """Generates a secure random string URL-safe."""
    return secrets.token_urlsafe(length)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_secrets.py <type>")
        sys.exit(1)
    
    secret_type = sys.argv[1]
    
    if secret_type == "fernet":
        print(generate_fernet_key(), end="")
    elif secret_type == "random":
        print(generate_secret(), end="")
    else:
        print(f"Unknown secret type: {secret_type}", file=sys.stderr)
        sys.exit(1)
