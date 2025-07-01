# src/app/infrastructure/messaging/publisher.py

import pika
import logging
import json
import uuid
from typing import Optional

from app.config.config import settings
from pika.exceptions import AMQPConnectionError

logger = logging.getLogger(__name__)


# This is your existing function, preserved without changes.
def publish_submission(submission_id: str, correlation_id: Optional[str] = None):
    """
    Publishes a submission ID and correlation ID to the specified RabbitMQ queue.
    This is a synchronous, blocking function.
    """
    connection = None
    # UPDATED: Use the new, more descriptive setting name
    queue_name = settings.RABBITMQ_SUBMISSION_QUEUE

    if not settings.RABBITMQ_URL:
        logger.error(
            "RABBITMQ_URL is not configured in settings. Cannot publish message."
        )
        raise ValueError("RABBITMQ_URL is not configured.")

    logger.debug(f"Attempting to publish to RabbitMQ queue '{queue_name}'.")
    try:
        parameters = pika.URLParameters(settings.RABBITMQ_URL)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(queue=queue_name, durable=True)

        message_body = {
            "submission_id": submission_id,
            "correlation_id": correlation_id or str(uuid.uuid4()),
        }

        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(message_body).encode("utf-8"),
            properties=pika.BasicProperties(
                delivery_mode=2,
            ),
        )
        logger.info(
            f"Successfully sent message to RabbitMQ queue '{queue_name}': '{submission_id}'"
        )
    except AMQPConnectionError as e:
        logger.error(
            f"Failed to connect to RabbitMQ using URL from settings. Error: {e}",
            exc_info=True,
        )
        raise
    except Exception as e:
        logger.error(
            f"An unexpected error occurred during RabbitMQ publish: {e}", exc_info=True
        )
        raise
    finally:
        if connection and connection.is_open:
            try:
                connection.close()
                logger.debug("RabbitMQ connection closed.")
            except Exception as close_err:
                logger.error(
                    f"Error closing RabbitMQ connection: {close_err}", exc_info=True
                )


# --- ADDED: New generic message publisher ---
def publish_message(
    queue_name: str, message_body: dict, correlation_id: Optional[str] = None
) -> bool:
    """
    Publishes a generic dictionary message to the specified RabbitMQ queue.
    Adopts the robust connection and error handling from publish_submission.

    Args:
        queue_name: The name of the queue to publish to.
        message_body: A dictionary to be sent as the message body.

    Returns:
        True if message was published successfully, False otherwise.
    """
    connection = None
    if not settings.RABBITMQ_URL:
        logger.error("RABBITMQ_URL is not configured. Cannot publish message.")
        return False

    logger.debug(f"Attempting to publish to RabbitMQ queue '{queue_name}'.")
    try:
        parameters = pika.URLParameters(settings.RABBITMQ_URL)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(queue=queue_name, durable=True)

        # Add correlation_id to the message body
        full_message_body = {
            **message_body,
            "correlation_id": correlation_id or str(uuid.uuid4()),
        }
        body_json = json.dumps(full_message_body)

        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=body_json.encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2),  # Make message persistent
        )
        logger.info(
            f"Successfully published message to queue '{queue_name}': {body_json}"
        )
        return True
    except Exception as e:
        logger.error(
            f"Failed to publish message to queue '{queue_name}': {e}", exc_info=True
        )
        return False
    finally:
        if connection and connection.is_open:
            connection.close()
