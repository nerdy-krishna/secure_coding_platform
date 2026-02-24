import logging
from typing import Optional
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from app.config.config import settings
from pydantic import EmailStr

logger = logging.getLogger(__name__)

def get_mail_config() -> Optional[ConnectionConfig]:
    from app.core.config_cache import SystemConfigCache
    smtp_config = SystemConfigCache.get_smtp_config()
    
    if smtp_config:
        try:
            return ConnectionConfig(
                MAIL_USERNAME=smtp_config.get("user", ""),
                MAIL_PASSWORD=smtp_config.get("password", ""),
                MAIL_FROM=smtp_config.get("from", ""),
                MAIL_PORT=int(smtp_config.get("port", 587)),
                MAIL_SERVER=smtp_config.get("host", ""),
                MAIL_STARTTLS=smtp_config.get("tls", True),
                MAIL_SSL_TLS=smtp_config.get("ssl", False),
                USE_CREDENTIALS=True,
                VALIDATE_CERTS=True
            )
        except Exception as e:
            logger.error(f"Error parsing dynamic SMTP config: {e}")
            # Fall through to env config if dynamic is malformed
            pass

    # Fallback to env config
    if not (settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD and settings.SMTP_FROM):
        return None

    return ConnectionConfig(
        MAIL_USERNAME=settings.SMTP_USER,
        MAIL_PASSWORD=settings.SMTP_PASSWORD,
        MAIL_FROM=settings.SMTP_FROM,
        MAIL_PORT=settings.SMTP_PORT,
        MAIL_SERVER=settings.SMTP_HOST,
        MAIL_STARTTLS=settings.SMTP_TLS,
        MAIL_SSL_TLS=settings.SMTP_SSL,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True
    )

async def send_password_reset_email(email_to: EmailStr, token: str, reset_url_base: str):
    config = get_mail_config()
    if not config:
        logger.error("SMTP configuration is incomplete. Cannot send password reset email.")
        return

    reset_url = f"{reset_url_base}?token={token}"
    
    html_content = f"""
    <html>
        <body>
            <h2>Password Reset / Setup</h2>
            <p>You have been invited to join the Secure Coding Platform or requested a password reset.</p>
            <p>Please click the link below to set your password:</p>
            <p><a href="{reset_url}">{reset_url}</a></p>
            <br>
            <p>If you did not request this, please ignore this email.</p>
        </body>
    </html>
    """

    message = MessageSchema(
        subject="Password Reset / Setup for Secure Coding Platform",
        recipients=[email_to],
        body=html_content,
        subtype=MessageType.html
    )

    try:
        fm = FastMail(config)
        await fm.send_message(message)
        logger.info(f"Password reset email sent successfully to {email_to}")
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email_to}: {e}", exc_info=True)
