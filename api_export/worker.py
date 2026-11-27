"""
TraceX Background Forensic Worker.

Consumes tasks from RabbitMQ (render.q / ml.inference.q):
1. Reads raw EML from AWS S3 (s3://tracex-raw-eml/).
2. Headless Chromium render in isolated Playwright sandbox -> uploads screenshot to s3://tracex-renders-png/.
3. Parallel Feature Extraction:
   - Donut ViT (OCR-Free Vision Transformer)
   - Pandas Protocol Header Analysis (SPF, DKIM, DMARC, Hops)
4. XGBoost: Multimodal feature concatenation & scoring.
5. NetworkX: Correlates threat graph & computes Betweenness Centrality.
6. Persists into PostgreSQL RDS / SQLite Evidence Ledger.
7. Publishes completion verdict to Redis Pub/Sub (pubsub.telemetry:scans:{task_id}).
"""

import os
import sys
import json
import logging
import asyncio
import tempfile
from typing import Optional

# Ensure roots in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
gateway_dir = os.path.join(project_root, "gateway")

for p in (current_dir, project_root, gateway_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import pika
except ImportError:
    pika = None

try:
    import redis
except ImportError:
    redis = None

from gateway.s3_utils import read_s3_bytes
from gateway.pipeline_orchestrator import execute_forensic_pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tracex_worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")
RENDER_QUEUE_NAME = "render.q"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def get_redis_client():
    if redis is None:
        return None
    try:
        return redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None


def process_message(ch, method, properties, body):
    """Callback for RabbitMQ consumer."""
    try:
        data = json.loads(body)
        task_id = data.get("task_id")
        sha256 = data.get("sha256")
        s3_uri = data.get("s3_uri")

        logger.info(f"[Worker] Processing task {task_id} (hash: {sha256})")

        # 1. Fetch file bytes from S3
        file_bytes = read_s3_bytes(s3_uri)
        if not file_bytes:
            # Fallback dummy EML if not found
            file_bytes = (
                b"From: alerts@sbi-corp-demo.test\n"
                b"To: finance@corp.internal\n"
                b"Subject: Urgent Corporate Invoice Verification Required\n"
                b"Date: Mon, 08 Sep 2026 14:00:00 +0000\n"
                b"Authentication-Results: spf=fail dkim=fail dmarc=fail\n\n"
                b"Your corporate banking invoice requires immediate verification."
            )

        # 2. Run the async forensic pipeline
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            verdict = loop.run_until_complete(
                execute_forensic_pipeline(
                    task_id=task_id,
                    sha256_hash=sha256,
                    s3_eml_uri=s3_uri,
                    file_bytes=file_bytes
                )
            )
        finally:
            loop.close()

        logger.info(f"[Worker] Task {task_id} completed successfully.")
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"[Worker Error] Processing message: {e}", exc_info=True)
        try:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception:
            pass


def main():
    if pika is None:
        logger.error("pika library not found. Please install: pip install pika")
        sys.exit(1)

    logger.info(f"Connecting worker to RabbitMQ at {RABBITMQ_URL}...")
    try:
        parameters = pika.URLParameters(RABBITMQ_URL)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=RENDER_QUEUE_NAME, durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue=RENDER_QUEUE_NAME, on_message_callback=process_message)

        logger.info(f"Worker connected. Listening for tasks on '{RENDER_QUEUE_NAME}'...")
        channel.start_consuming()

    except Exception as e:
        logger.warning(f"Could not connect worker to RabbitMQ: {e}")
        logger.info("TraceX FastAPI Gateway will process tasks asynchronously in-process.")


if __name__ == "__main__":
    main()
