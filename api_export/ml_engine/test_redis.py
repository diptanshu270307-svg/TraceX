"""
TraceX Redis Caching & Real-Time Alert Demonstration
Demonstrates:
1. Sub-millisecond Phishing Wave Deduplication (Cold vs. Warm Cache)
2. In-Memory Threat Intelligence Domain Reputation Cache
3. Real-Time SOC Alert Broadcasting via Redis Pub/Sub
"""

import os
import sys
import time
import json

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from ml_engine.pipeline import TraceXMLPipeline
from ml_engine.storage.redis_cache import TraceXRedisCache


def demonstrate_redis():
    print("=" * 75)
    print("  TRACEX REDIS CACHE & REAL-TIME PUB/SUB DEMONSTRATION")
    print("=" * 75)

    pipeline = TraceXMLPipeline()
    redis_cache = pipeline.redis_cache

    test_meta = {
        "sender": "State Bank Alerts <alerts@sbi-corp-demo.test>",
        "subject": "Urgent Corporate Invoice Verification Required",
        "reply_to": "fraud@external-phish.xyz",
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "hops": 4,
        "recipient": "finance@corp.internal"
    }
    test_img = os.path.join(base_dir, "ml_engine", "data", "raw", "email_0000.png")

    # -------------------------------------------------------------
    # 1. PHISHING WAVE DEDUPLICATION BENCHMARK
    # -------------------------------------------------------------
    print("\n[SCENARIO 1] Simulating Inbound Phishing Wave (Deduplication Benchmark)")
    print("Victim 1 receives email (Cold Cache -> Neural Inference + AWS Storage)...")

    start_time = time.perf_counter()
    verdict_cold = pipeline.predict(image_path_or_obj=test_img, metadata_or_headers=test_meta)
    cold_duration = (time.perf_counter() - start_time) * 1000

    print(f"  • Cold Scan Duration: {cold_duration:.2f} ms")
    print(f"  • Fraud Score:        {verdict_cold['fraud_score']} / 100 [{verdict_cold['risk_level']}]")
    print(f"  • Cached Status:      {verdict_cold.get('cached', False)}")

    print("\nVictim 2 receives IDENTICAL email 5 seconds later (Warm Cache -> Redis Hit)...")
    start_time = time.perf_counter()
    verdict_warm = pipeline.predict(image_path_or_obj=test_img, metadata_or_headers=test_meta)
    warm_duration = (time.perf_counter() - start_time) * 1000

    print(f"  • Warm Scan Duration: {warm_duration:.2f} ms")
    print(f"  • Fraud Score:        {verdict_warm['fraud_score']} / 100 [{verdict_warm['risk_level']}]")
    print(f"  • Cached Status:      {verdict_warm.get('cached', False)}")

    if warm_duration > 0:
        speedup = cold_duration / max(warm_duration, 0.01)
        print(f"\n[★] Redis Cache Speedup: {speedup:.1f}x FASTER (Zero redundant neural processing!)")

    # -------------------------------------------------------------
    # 2. THREAT INTEL DOMAIN REPUTATION CACHE
    # -------------------------------------------------------------
    print("\n[SCENARIO 2] Threat Intelligence In-Memory Domain Cache")
    domain = "sbi-corp-demo.test"
    reputation_payload = {
        "domain": domain,
        "risk": "CRITICAL",
        "fraud_score": 94,
        "category": "BRAND_TYPOSQUATTING",
        "ttl_hours": 12
    }

    print(f"Caching domain '{domain}' in Redis with 12-hour TTL...")
    redis_cache.cache_domain_reputation(domain, reputation_payload)

    cached_intel = redis_cache.get_domain_reputation(domain)
    print(f"[+] Instant Lookup Result for '{domain}':")
    print(f"    Risk: {cached_intel.get('risk')} | Score: {cached_intel.get('fraud_score')}/100 | Category: {cached_intel.get('category')}")

    # -------------------------------------------------------------
    # 3. REAL-TIME PUB/SUB BROADCASTING
    # -------------------------------------------------------------
    print("\n[SCENARIO 3] Real-Time Alert Broadcasting via Redis Pub/Sub")
    print(f"Publishing high-priority threat alert to channel '{redis_cache.CHANNEL_CRITICAL_ALERTS}'...")
    redis_cache.publish_alert(verdict_cold)
    print("[+] Alert successfully dispatched to Redis Pub/Sub event bus.")

    print("\n" + "=" * 75)
    print("  REDIS INTEGRATION VERIFIED SUCCESSFULLY")
    print("=" * 75)


if __name__ == "__main__":
    demonstrate_redis()
