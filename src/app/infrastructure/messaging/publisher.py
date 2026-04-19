# src/app/infrastructure/messaging/publisher.py

import asyncio
import json
import logging
import uuid
from typing import Optional

import aio_pika
from aio_pika.abc import AbstractRobustChannel, AbstractRobustConnection

from app.config.config import settings

logger = logging.getLogger(__name__)

# Module-level singleton connection/channel. aio_pika.connect_robust reconnects
# automatically on AMQP failures, so we reuse one connection + channel across
# publishes instead of the previous pattern of opening a new blocking pika
# connection per message (which stalled the event loop in async request paths).
_connection: Optional[AbstractRobustConnection] = None
_channel: Optional[AbstractRobustChannel] = None
_lock = asyncio.Lock()
_declared_queues: set[str] = set()


async def _get_channel() -> AbstractRobustChannel:
    global _connection, _channel

    async with _lock:
        if _connection is None or _connection.is_closed:
            logger.debug("Opening robust RabbitMQ connection.")
            _connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
            # Reconnect invalidates any prior channel and the queue-declared
            # cache is per-channel, so reset both.
            _channel = None
            _declared_queues.clear()
        if _channel is None or _channel.is_closed:
            _channel = await _connection.channel()

    return _channel


async def _ensure_queue(channel: AbstractRobustChannel, queue_name: str) -> None:
    if queue_name in _declared_queues:
        return
    await channel.declare_queue(queue_name, durable=True)
    _declared_queues.add(queue_name)


async def publish_message(
    queue_name: str,
    message_body: dict,
    correlation_id: Optional[str] = None,
) -> bool:
    """Publishes a dict message to a durable queue. Returns True on success."""
    if not settings.RABBITMQ_URL:
        logger.error("RABBITMQ_URL is not configured. Cannot publish message.")
        return False

    full_body = {
        **message_body,
        "correlation_id": correlation_id or str(uuid.uuid4()),
    }

    try:
        channel = await _get_channel()
        await _ensure_queue(channel, queue_name)
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps(full_body).encode("utf-8"),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=queue_name,
        )
        logger.info(
            "Published message to queue.",
            extra={"queue": queue_name, "body": full_body},
        )
        return True
    except Exception as e:
        logger.error(
            f"Failed to publish message to queue '{queue_name}': {e}",
            exc_info=True,
        )
        return False


async def close_publisher() -> None:
    """Closes the shared connection — call from the FastAPI lifespan shutdown."""
    global _connection, _channel
    async with _lock:
        if _connection is not None and not _connection.is_closed:
            try:
                await _connection.close()
            except Exception as e:
                logger.warning(f"Error closing RabbitMQ publisher connection: {e}")
        _connection = None
        _channel = None
        _declared_queues.clear()
