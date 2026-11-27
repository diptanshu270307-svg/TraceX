import json
import logging
import os
import aio_pika

logger = logging.getLogger(__name__)

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")
RENDER_QUEUE_NAME = "render.q"

_connection = None
_channel = None

async def get_rabbitmq_channel():
    """
    Establishes a connection and channel to RabbitMQ.
    Reuses the connection if it already exists.
    """
    global _connection, _channel
    if _connection is None or _connection.is_closed:
        try:
            logger.info(f"Connecting to RabbitMQ at {RABBITMQ_URL}")
            _connection = await aio_pika.connect_robust(RABBITMQ_URL, timeout=3.0)
            _channel = await _connection.channel()
            await _channel.declare_queue(RENDER_QUEUE_NAME, durable=True)
        except Exception as e:
            logger.warning(f"RabbitMQ unavailable ({e}). Using in-process worker pipeline fallback.")
            return None
        
    return _channel

async def publish_render_task(task_id: str, sha256_hash: str, s3_uri: str) -> bool:
    """
    Publishes a task to the `render.q` in RabbitMQ.
    Returns True if published to RabbitMQ, False if broker unavailable.
    """
    try:
        channel = await get_rabbitmq_channel()
        if channel is None:
            return False
            
        message_body = {
            "task_id": task_id,
            "sha256": sha256_hash,
            "s3_uri": s3_uri
        }
        
        message = aio_pika.Message(
            body=json.dumps(message_body).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        )
        
        await channel.default_exchange.publish(
            message,
            routing_key=RENDER_QUEUE_NAME
        )
        logger.info(f"Successfully published task {task_id} to RabbitMQ {RENDER_QUEUE_NAME}")
        return True
        
    except Exception as e:
        logger.warning(f"Failed to publish task to RabbitMQ ({e}). Falling back to internal worker.")
        return False

async def close_rabbitmq_connection():
    """Closes the RabbitMQ connection gracefully on shutdown."""
    global _connection
    if _connection and not _connection.is_closed:
        try:
            await _connection.close()
            logger.info("Closed RabbitMQ connection.")
        except Exception:
            pass
