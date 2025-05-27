# src/app/utils/rabbitmq_utils.py
import pika
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()  # Load environment variables from .env

# RabbitMQ Configuration from environment variables
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT_DOCKER", "5672") # Port used by services within Docker network
RABBITMQ_USER = os.getenv("RABBITMQ_DEFAULT_USER", "devuser_scp") # Ensure consistency with .env
RABBITMQ_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", "YourStrongRabbitPassword!") # Ensure consistency with .env

# Queue name from environment variable, defaulting if not set
# This was referenced in api_graph.py, so ensure it's defined.
CODE_QUEUE = os.getenv("CODE_QUEUE", "code_analysis_queue") 

def publish_to_rabbitmq(message_body_str: str): # Renamed for clarity
    """
    Publishes a message (string) to the specified RabbitMQ queue (CODE_QUEUE).
    Handles connection and channel setup/teardown.
    This is a synchronous function; use with run_in_threadpool in async contexts.
    """
    connection = None
    logger.debug(f"Attempting to publish to RabbitMQ. Host: {RABBITMQ_HOST}, Port: {RABBITMQ_PORT}, Queue: {CODE_QUEUE}")
    try:
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=int(RABBITMQ_PORT), # Ensure port is integer
            credentials=credentials,
            heartbeat=600, # Keep connection alive
            blocked_connection_timeout=300 # Timeout for blocked connections
        )
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        # Declare the queue as durable (it will survive a broker restart)
        channel.queue_declare(queue=CODE_QUEUE, durable=True)

        channel.basic_publish(
            exchange='',             # Default exchange
            routing_key=CODE_QUEUE,  # Queue name
            body=message_body_str.encode('utf-8'), # Ensure message is bytes
            properties=pika.BasicProperties(
                delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE, # Make message persistent
            )
        )
        logger.info(f"Successfully sent message to RabbitMQ queue '{CODE_QUEUE}': '{message_body_str[:50]}...'")
    except pika.exceptions.AMQPConnectionError as e:
        logger.error(f"Failed to connect to RabbitMQ at {RABBITMQ_HOST}:{RABBITMQ_PORT}. Error: {e}", exc_info=True)
        raise # Re-raise the exception to be handled by the caller
    except Exception as e:
        logger.error(f"An unexpected error occurred during RabbitMQ publish: {e}", exc_info=True)
        raise # Re-raise
    finally:
        if connection and connection.is_open:
            try:
                connection.close()
                logger.debug("RabbitMQ connection closed.")
            except Exception as close_err:
                logger.error(f"Error closing RabbitMQ connection: {close_err}", exc_info=True)