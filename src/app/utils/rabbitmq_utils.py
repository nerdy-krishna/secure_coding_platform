import pika
import logging
import json

from app.core.config import settings
from pika.exceptions import AMQPConnectionError

logger = logging.getLogger(__name__)

def publish_submission(submission_id: str):
    """
    Publishes a submission ID to the specified RabbitMQ queue.
    This is a synchronous, blocking function.
    """
    connection = None
    queue_name = settings.CODE_QUEUE
    
    if not settings.RABBITMQ_URL:
        logger.error("RABBITMQ_URL is not configured in settings. Cannot publish message.")
        raise ValueError("RABBITMQ_URL is not configured.")

    logger.debug(
        f"Attempting to publish to RabbitMQ queue '{queue_name}'."
    )
    try:
        parameters = pika.URLParameters(settings.RABBITMQ_URL)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(queue=queue_name, durable=True)

        message_body = json.dumps({"submission_id": submission_id})

        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=message_body.encode("utf-8"),
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