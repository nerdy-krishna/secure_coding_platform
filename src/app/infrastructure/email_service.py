import hashlib
import html
import logging
from typing import Optional
from urllib.parse import urlencode, urlsplit

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from app.config.config import settings
from pydantic import EmailStr

logger = logging.getLogger(__name__)


def get_mail_config() -> Optional[ConnectionConfig]:
    from app.core.config_cache import SystemConfigCache

    smtp_config = SystemConfigCache.get_smtp_config()

    if smtp_config:
        try:
            # V12.3.1: refuse to send mail in cleartext. At least one of STARTTLS or
            # implicit TLS must be enabled; tls=False, ssl=False is rejected.
            starttls = smtp_config.get("tls", True)
            ssl_tls = smtp_config.get("ssl", False)
            if not (starttls or ssl_tls):
                logger.critical(
                    "email_service.cleartext_smtp_rejected",
                    extra={"branch": "dynamic_config"},
                )
                return None
            return ConnectionConfig(
                MAIL_USERNAME=smtp_config.get("user", ""),
                MAIL_PASSWORD=smtp_config.get("password", ""),
                MAIL_FROM=smtp_config.get("from", ""),
                MAIL_PORT=int(smtp_config.get("port", 587)),
                MAIL_SERVER=smtp_config.get("host", ""),
                MAIL_STARTTLS=starttls,
                MAIL_SSL_TLS=ssl_tls,
                USE_CREDENTIALS=True,
                VALIDATE_CERTS=True,
            )
        except Exception as e:
            logger.error(
                "email_service.smtp_config_parse_failed",
                extra={"error_class": e.__class__.__name__},
                exc_info=True,
            )
            # Fall through to env config if dynamic is malformed
            pass

    # Fallback to env config
    if not (
        settings.SMTP_HOST
        and settings.SMTP_USER
        and settings.SMTP_PASSWORD
        and settings.SMTP_FROM
    ):
        return None

    # V12.3.1: env-fallback branch — refuse to send mail in cleartext.
    env_starttls = settings.SMTP_TLS
    env_ssl = settings.SMTP_SSL
    if not (env_starttls or env_ssl):
        logger.critical(
            "email_service.cleartext_smtp_rejected",
            extra={"branch": "env_fallback"},
        )
        return None
    # SMTP_PASSWORD is Optional[SecretStr]; fastapi-mail wants a plain string.
    _smtp_password = (
        settings.SMTP_PASSWORD.get_secret_value()
        if hasattr(settings.SMTP_PASSWORD, "get_secret_value")
        else str(settings.SMTP_PASSWORD or "")
    )
    return ConnectionConfig(
        MAIL_USERNAME=settings.SMTP_USER,
        MAIL_PASSWORD=_smtp_password,
        MAIL_FROM=settings.SMTP_FROM,
        MAIL_PORT=settings.SMTP_PORT,
        MAIL_SERVER=settings.SMTP_HOST,
        MAIL_STARTTLS=env_starttls,
        MAIL_SSL_TLS=env_ssl,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True,
    )


async def send_password_reset_email(
    email_to: EmailStr, token: str, reset_url_base: str
):
    """Send a password-reset / setup email to ``email_to``.

    V06.3.6 note: email is a *recovery* transport, not an authentication factor. At
    L3 this transport must only be reachable when the account has at least one
    non-email second factor enrolled. Enforcement of that policy lives in the
    auth layer (see ``app.infrastructure.auth.manager``); this helper only
    dispatches the message.
    """
    # V02.2.1 / V02.2.3: validate reset_url_base origin against an allow list before composing
    # the URL. A token issued for SCCAP must only ride on a SCCAP-configured origin.
    from app.core.config_cache import SystemConfigCache

    allowed_origins = set(SystemConfigCache.get_allowed_origins() or []) | set(
        getattr(settings, "ALLOWED_ORIGINS", []) or []
    )
    parsed_base = urlsplit(reset_url_base)
    # V01.2.2: protocol allow list — reject anything that is not http(s).
    if parsed_base.scheme not in ("http", "https"):
        logger.error(
            "password_reset_email.invalid_scheme",
            extra={"scheme": parsed_base.scheme or ""},
        )
        return
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    if allowed_origins and origin not in allowed_origins:
        logger.error(
            "password_reset_email.origin_not_allowed",
            extra={"origin": origin},
        )
        return

    config = get_mail_config()
    if not config:
        logger.error(
            "password_reset_email.smtp_misconfigured",
            extra={"reason": "SMTP configuration is incomplete."},
        )
        return

    # V01.2.2: URL-encode the token in its query/fragment context.
    # V06.4.1 / V14.2.1: deliver the token via URL fragment so it never reaches HTTP servers,
    # proxies, browser history, or Referer headers. The frontend reset page reads
    # window.location.hash and posts the token in the request body.
    encoded_token_pair = urlencode({"token": token})
    reset_url = f"{reset_url_base}#{encoded_token_pair}"

    # V01.1.2 / V01.2.1: HTML-escape the URL before placing it into href= and link text.
    safe_url = html.escape(reset_url, quote=True)
    # V06.4.3: surface link expiration / single-use semantics. Parameterised from settings
    # when available; falls back to a sensible default.
    reset_token_lifetime_minutes = getattr(settings, "RESET_TOKEN_LIFETIME_MINUTES", 60)
    html_content = f"""
    <html>
        <body>
            <h2>Password Reset / Setup</h2>
            <p>You have been invited to join SCCAP, or requested a password reset.</p>
            <p>Please click the link below to set your password:</p>
            <p><a href="{safe_url}">{safe_url}</a></p>
            <p>This link expires in {reset_token_lifetime_minutes} minutes and can only be used once.</p>
            <br>
            <p>If you did not request this, please ignore this email.</p>
        </body>
    </html>
    """

    message = MessageSchema(
        subject="Password Reset / Setup for SCCAP",
        recipients=[email_to],
        body=html_content,
        subtype=MessageType.html,
    )

    try:
        fm = FastMail(config)
        await fm.send_message(message)
        logger.info(
            "password_reset_email.sent",
            extra={
                "recipient_hash": hashlib.sha256(email_to.encode()).hexdigest()[:12]
            },
        )
    except Exception as e:
        logger.error(
            "password_reset_email.failed",
            extra={
                "recipient_hash": hashlib.sha256(email_to.encode()).hexdigest()[:12],
                "error_class": e.__class__.__name__,
            },
            exc_info=True,
        )
