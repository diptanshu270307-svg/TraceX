"""
auth_s3.py — Pure AWS S3 Authentication & Session Management for TraceX.

Stores user credentials, analyst profiles, and active session tokens exclusively in AWS S3:
- s3://tracex-evidence-ledger/auth/users/{username}.json
- s3://tracex-evidence-ledger/auth/sessions/{token}.json

Zero local database tables or SQLite. Salted SHA-256 password hashing.
"""

from __future__ import annotations

import os
import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from .s3_utils import put_s3_json, get_s3_json, delete_s3_object, S3_EVIDENCE_BUCKET

logger = logging.getLogger(__name__)


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    """Hashes a password with a cryptographic salt using SHA-256."""
    if not salt:
        salt = secrets.token_hex(16)
    salted = f"{salt}:{password}".encode("utf-8")
    pwd_hash = hashlib.sha256(salted).hexdigest()
    return {"salt": salt, "hash": pwd_hash}


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Verifies candidate password against stored salt and expected hash."""
    salted = f"{salt}:{password}".encode("utf-8")
    actual_hash = hashlib.sha256(salted).hexdigest()
    return secrets.compare_digest(actual_hash, expected_hash)


def register_user_in_s3(
    username: str,
    email: str,
    password: str,
    role: str = "Lead Cyber Analyst",
    organization: str = "TraceX Threat Defense Command"
) -> Dict[str, Any]:
    """
    Registers a new analyst and stores the profile directly in AWS S3.
    """
    username = username.strip().lower()
    user_key = f"auth/users/{username}.json"

    # Check if already exists in S3
    existing = get_s3_json(S3_EVIDENCE_BUCKET, user_key)
    if existing:
        raise ValueError(f"Username '{username}' already exists in AWS S3 authentication directory.")

    pwd_info = hash_password(password)
    user_data = {
        "username": username,
        "email": email.strip().lower(),
        "password_hash": pwd_info["hash"],
        "salt": pwd_info["salt"],
        "role": role,
        "organization": organization,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": None
    }

    put_s3_json(S3_EVIDENCE_BUCKET, user_key, user_data)
    logger.info(f"[AWS S3 Auth] Registered new user '{username}' at s3://{S3_EVIDENCE_BUCKET}/{user_key}")
    return {
        "username": user_data["username"],
        "email": user_data["email"],
        "role": user_data["role"],
        "organization": user_data["organization"],
        "created_at": user_data["created_at"]
    }


def authenticate_user_with_s3(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticates username and password against AWS S3.
    Returns session dict with token if valid, None otherwise.
    """
    username = username.strip().lower()
    user_key = f"auth/users/{username}.json"

    user_data = get_s3_json(S3_EVIDENCE_BUCKET, user_key)
    if not user_data:
        # Check if default admin account needs auto-initialization
        if username == "admin" and password == "tracex2026!":
            register_user_in_s3("admin", "admin@tracex.defense", "tracex2026!", role="Chief Forensic Officer")
            user_data = get_s3_json(S3_EVIDENCE_BUCKET, user_key)
        else:
            return None

    if not verify_password(password, user_data["salt"], user_data["password_hash"]):
        return None

    # Generate session token and store in AWS S3
    token = f"tracex_sess_{secrets.token_hex(24)}"
    session_key = f"auth/sessions/{token}.json"
    session_data = {
        "token": token,
        "username": username,
        "email": user_data.get("email"),
        "role": user_data.get("role", "Security Analyst"),
        "organization": user_data.get("organization", "TraceX Command"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    }

    put_s3_json(S3_EVIDENCE_BUCKET, session_key, session_data)

    # Update last login in user profile
    user_data["last_login"] = session_data["created_at"]
    put_s3_json(S3_EVIDENCE_BUCKET, user_key, user_data)

    logger.info(f"[AWS S3 Auth] Successfully authenticated '{username}', session created in S3")
    return session_data


def verify_session_in_s3(token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies that a session token exists and is valid in AWS S3.
    """
    if not token:
        return None

    session_key = f"auth/sessions/{token}.json"
    session_data = get_s3_json(S3_EVIDENCE_BUCKET, session_key)
    if not session_data:
        return None

    expires_at = datetime.fromisoformat(session_data["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        logger.info(f"[AWS S3 Auth] Session token '{token[:16]}...' expired.")
        return None

    return session_data


def revoke_session_in_s3(token: str) -> bool:
    """
    Revokes an active session token, deleting it from AWS S3 and local vault.
    """
    if not token:
        return False
    session_key = f"auth/sessions/{token}.json"
    deleted = delete_s3_object(S3_EVIDENCE_BUCKET, session_key)
    logger.info(f"[AWS S3 Auth] Session '{token[:16]}...' revoked and purged from AWS S3.")
    return deleted


def init_default_admin():
    """Provisions default analyst credentials in S3 if not present."""
    user_key = "auth/users/admin.json"
    if not get_s3_json(S3_EVIDENCE_BUCKET, user_key):
        try:
            register_user_in_s3("admin", "admin@tracex.defense", "tracex2026!", role="Lead Cyber Analyst")
        except Exception:
            pass


# Provision default admin on startup
init_default_admin()
