"""
TraceX Redis In-Memory Cache & Pub/Sub Manager
Handles:
1. Sub-millisecond Deduplication & Verdict Caching (Instant SHA-256 Hit)
2. Threat Intelligence Domain & IP Reputation Caching (TTL Expiry)
3. Real-time SOC Alert Broadcasting via Redis Pub/Sub
"""

import os
import json
from typing import Dict, Any, Optional

from ml_engine.config import (
    REDIS_HOST,
    REDIS_PORT,
    REDIS_PASSWORD,
    REDIS_DB,
    REDIS_URL
)

# Check for redis-py
REDIS_AVAILABLE = False
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    pass


class TraceXRedisCache:
    """Manages Redis in-memory caching and real-time alert pub/sub."""

    CHANNEL_CRITICAL_ALERTS = "tracex:alerts:critical"
    CHANNEL_ALL_SCANS = "tracex:scans:stream"

    PREFIX_VERDICT = "tracex:verdict:"
    PREFIX_DOMAIN = "tracex:intel:domain:"
    PREFIX_IP = "tracex:intel:ip:"

    def __init__(
        self,
        host: str = REDIS_HOST,
        port: int = REDIS_PORT,
        password: Optional[str] = REDIS_PASSWORD,
        db: int = REDIS_DB
    ):
        self.host = host
        self.port = port
        self.password = password
        self.db = db

        self.client = None
        self.is_connected = False
        self._local_cache = {}  # In-memory fallback if Redis server is offline

        self._init_connection()

    def _init_connection(self) -> None:
        if not REDIS_AVAILABLE:
            print("[!] 'redis' package not installed. Running Redis in Local Emulation Mode.")
            return

        try:
            self.client = redis.Redis(
                host=self.host,
                port=self.port,
                password=self.password,
                db=self.db,
                socket_timeout=1.5,
                decode_responses=True
            )
            self.client.ping()
            self.is_connected = True
            print(f"[+] Connected to Redis at {self.host}:{self.port} (DB: {self.db})")
        except Exception as e:
            print(f"[!] Redis server unreachable ({e}). Using Local In-Memory Cache.")
            self.is_connected = False

    # -------------------------------------------------------------
    # 1. SHA-256 VERDICT DEDUPLICATION (Instant Cache Hit)
    # -------------------------------------------------------------
    def get_cached_verdict(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached verdict by SHA-256 hash. Returns None if not found."""
        key = f"{self.PREFIX_VERDICT}{sha256_hash}"

        if self.is_connected and self.client:
            try:
                data = self.client.get(key)
                if data:
                    return json.loads(data)
            except Exception as e:
                print(f"[-] Redis get_verdict error: {e}")

        return self._local_cache.get(key)

    def cache_verdict(self, sha256_hash: str, verdict: Dict[str, Any], ttl_seconds: int = 86400) -> None:
        """Caches an email verdict for 24 hours (86,400s) to handle phishing waves instantly."""
        key = f"{self.PREFIX_VERDICT}{sha256_hash}"
        serialized = json.dumps(verdict)

        if self.is_connected and self.client:
            try:
                self.client.setex(key, ttl_seconds, serialized)
                return
            except Exception as e:
                print(f"[-] Redis cache_verdict error: {e}")

        self._local_cache[key] = verdict

    # -------------------------------------------------------------
    # 2. THREAT INTEL DOMAIN / IP REPUTATION CACHE
    # -------------------------------------------------------------
    def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """Quick look-up for previously analyzed domains."""
        key = f"{self.PREFIX_DOMAIN}{domain.lower()}"
        if self.is_connected and self.client:
            try:
                val = self.client.get(key)
                if val:
                    return json.loads(val)
            except Exception:
                pass
        return self._local_cache.get(key)

    def cache_domain_reputation(self, domain: str, reputation: Dict[str, Any], ttl_seconds: int = 43200) -> None:
        """Caches domain reputation (default TTL: 12 hours)."""
        key = f"{self.PREFIX_DOMAIN}{domain.lower()}"
        serialized = json.dumps(reputation)

        if self.is_connected and self.client:
            try:
                self.client.setex(key, ttl_seconds, serialized)
                return
            except Exception:
                pass
        self._local_cache[key] = reputation

    # -------------------------------------------------------------
    # 3. REAL-TIME PUB/SUB ALERT BROADCASTING
    # -------------------------------------------------------------
    def publish_alert(self, verdict: Dict[str, Any]) -> None:
        """Publishes a verdict event to Redis Pub/Sub for live SOC dashboard streaming."""
        payload = json.dumps({
            "event": "NEW_FORENSIC_SCAN",
            "scan_id": verdict.get("scan_id"),
            "fraud_score": verdict.get("fraud_score"),
            "risk_level": verdict.get("risk_level"),
            "classification": verdict.get("classification"),
            "sha256": verdict.get("sha256_hash"),
            "s3_uri": verdict.get("s3_uri"),
            "timestamp": verdict.get("timestamp")
        })

        if self.is_connected and self.client:
            try:
                # Publish to all scans stream
                self.client.publish(self.CHANNEL_ALL_SCANS, payload)
                # If CRITICAL or HIGH, publish to high-priority alert channel
                if verdict.get("risk_level") in ["CRITICAL", "HIGH"]:
                    self.client.publish(self.CHANNEL_CRITICAL_ALERTS, payload)
                    print(f"[*] [Redis Pub/Sub] Dispatched HIGH-RISK alert to '{self.CHANNEL_CRITICAL_ALERTS}'")
            except Exception as e:
                print(f"[-] Redis publish error: {e}")
        else:
            if verdict.get("risk_level") in ["CRITICAL", "HIGH"]:
                print(f"[*] [Redis Pub/Sub (Emulation)] Alert pushed: [{verdict.get('risk_level')}] Score {verdict.get('fraud_score')}/100")
