import asyncio
import logging
import json
import os
import redis.asyncio as redis

logger = logging.getLogger(__name__)

# Configurable Redis URL
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

async def subscribe_to_task_updates(task_id: str, queue: asyncio.Queue):
    """
    Subscribes to Redis Pub/Sub for a specific task_id.
    Yields or pushes messages into the provided asyncio.Queue so the WebSocket can read them.
    If Redis is unavailable, relays from the internal memory queue.
    """
    logger.info(f"Subscribing to updates for task {task_id}")
    client = None
    pubsub = None
    channel_name = f"pubsub.telemetry:scans:{task_id}"

    try:
        # Create an async redis client with short connect timeout
        client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2.0)
        pubsub = client.pubsub()
        await pubsub.subscribe(channel_name)
        
        # Listen for messages from Redis Pub/Sub
        async for message in pubsub.listen():
            if message['type'] == 'message':
                data = message['data']
                try:
                    parsed = json.loads(data)
                    await queue.put(parsed)
                    
                    if parsed.get("status") in ["completed", "failed"]:
                        break
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode Redis message: {data}")
                    
    except Exception as e:
        logger.info(f"Redis Pub/Sub notice for task {task_id}: {e}. Listening on local async queue.")
        # When Redis is not available, queue messages are fed directly by pipeline_orchestrator
        while True:
            await asyncio.sleep(0.5)
            # The WebSocket loop itself reads from queue, so this task just stays alive
    finally:
        if pubsub:
            try:
                await pubsub.unsubscribe(channel_name)
            except Exception:
                pass
        if client:
            try:
                await client.aclose()
            except Exception:
                pass
        logger.info(f"Closed Redis subscriber task for {task_id}")
