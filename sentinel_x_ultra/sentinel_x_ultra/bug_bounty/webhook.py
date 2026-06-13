"""
BUG BOUNTY WEBHOOK MANAGER — Fires configurable webhooks for policy decisions.

Provides:
- Webhook configuration (URL, events to subscribe to)
- Firing webhooks via HTTP POST with JSON payloads
- Persistence to JSON file
- Event type definitions
"""

import collections
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ── Event Types ──────────────────────────────────────────────────────────────

WEBHOOK_EVENT_POLICY_DECISION = "policy_decision_made"
WEBHOOK_EVENT_PIPELINE_COMPLETED = "pipeline_completed"

ALL_EVENTS = [
    WEBHOOK_EVENT_POLICY_DECISION,
    WEBHOOK_EVENT_PIPELINE_COMPLETED,
]


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    url: str = ""
    enabled: bool = True
    events: list[str] = field(default_factory=lambda: list(ALL_EVENTS))
    secret: str = ""  # Optional HMAC secret for payload signing
    headers: dict[str, str] = field(default_factory=dict)
    max_retries: int = 3
    timeout_seconds: int = 10
    rate_limit_max_per_minute: int = 60  # Max webhooks per minute (sliding window)
    rate_limit_max_per_hour: int = 1000  # Max webhooks per hour (sliding window)


@dataclass
class WebhookDelivery:
    """Record of a webhook delivery attempt."""
    id: str = ""
    event: str = ""
    url: str = ""
    status_code: int = 0
    success: bool = False
    error: str = ""
    timestamp: str = ""
    payload_preview: str = ""


# ── Default storage path ────────────────────────────────────────────────────

DEFAULT_WEBHOOK_STORAGE = Path.home() / ".sentinel-x" / "webhook_config.json"


class WebhookManager:
    """Manages webhook configuration and firing for bug bounty policy decisions."""

    def __init__(self, storage_path: Path | None = None):
        self._config: WebhookConfig = WebhookConfig()
        self._delivery_log: list[WebhookDelivery] = []
        self._storage_path = storage_path or DEFAULT_WEBHOOK_STORAGE
        # Rate limiting: event_type -> deque of delivery timestamps
        self._rate_limit_timestamps: dict[str, collections.deque] = {}
        self._load_config()

    # ── Config Management ───────────────────────────────────────────────────

    def get_config(self) -> WebhookConfig:
        """Get the current webhook configuration."""
        return self._config

    def update_config(self, config: WebhookConfig) -> WebhookConfig:
        """Update webhook configuration and persist to disk."""
        self._config = config
        self._save_config()
        return self._config

    def update_url(self, url: str) -> WebhookConfig:
        """Update just the webhook URL."""
        self._config.url = url
        self._config.enabled = bool(url.strip())
        self._save_config()
        return self._config

    def set_events(self, events: list[str]) -> WebhookConfig:
        """Set which events trigger the webhook."""
        # Validate events
        valid_events = [e for e in events if e in ALL_EVENTS]
        self._config.events = valid_events if valid_events else list(ALL_EVENTS)
        self._config.enabled = bool(self._config.url.strip())
        self._save_config()
        return self._config

    def is_enabled_for(self, event: str) -> bool:
        """Check if webhook is enabled for a specific event."""
        return (
            self._config.enabled
            and bool(self._config.url.strip())
            and event in self._config.events
        )

    def get_delivery_log(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent webhook delivery attempts."""
        return [asdict(d) for d in self._delivery_log[-limit:]]

    def get_rate_limit_stats(self) -> dict[str, Any]:
        """Get current rate limit statistics."""
        now = datetime.now(timezone.utc)
        stats = {}
        for event, timestamps in self._rate_limit_timestamps.items():
            # Count in last minute
            one_min_ago = now - timedelta(minutes=1)
            one_hour_ago = now - timedelta(hours=1)
            last_minute = sum(1 for t in timestamps if t > one_min_ago)
            last_hour = sum(1 for t in timestamps if t > one_hour_ago)
            stats[event] = {
                "in_last_minute": last_minute,
                "in_last_hour": last_hour,
                "max_per_minute": self._config.rate_limit_max_per_minute,
                "max_per_hour": self._config.rate_limit_max_per_hour,
            }
        return stats

    # ── Persistence ─────────────────────────────────────────────────────────

    def _load_config(self):
        """Load webhook config from disk."""
        try:
            if self._storage_path.exists():
                data = json.loads(self._storage_path.read_text(encoding="utf-8"))
                self._config = WebhookConfig(
                    url=data.get("url", ""),
                    enabled=data.get("enabled", True),
                    events=data.get("events", list(ALL_EVENTS)),
                    secret=data.get("secret", ""),
                    headers=data.get("headers", {}),
                    max_retries=data.get("max_retries", 3),
                    timeout_seconds=data.get("timeout_seconds", 10),
                    rate_limit_max_per_minute=data.get("rate_limit_max_per_minute", 60),
                    rate_limit_max_per_hour=data.get("rate_limit_max_per_hour", 1000),
                )
        except Exception:
            # If loading fails, use defaults
            self._config = WebhookConfig()

    def _save_config(self):
        """Persist webhook config to disk."""
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "url": self._config.url,
                "enabled": self._config.enabled,
                "events": self._config.events,
                "secret": self._config.secret,
                "headers": self._config.headers,
                "max_retries": self._config.max_retries,
                "timeout_seconds": self._config.timeout_seconds,
                "rate_limit_max_per_minute": self._config.rate_limit_max_per_minute,
                "rate_limit_max_per_hour": self._config.rate_limit_max_per_hour,
            }
            self._storage_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception as e:
            print(f"[WEBHOOK] Failed to save config: {e}")

    # ── Firing Webhooks ─────────────────────────────────────────────────────

    def _check_rate_limit(self, event: str) -> bool:
        """Check if a webhook for this event is allowed under rate limits.

        Uses a sliding window algorithm. Returns True if allowed, False if rate limited.
        """
        now = datetime.now(timezone.utc)
        max_per_minute = self._config.rate_limit_max_per_minute
        max_per_hour = self._config.rate_limit_max_per_hour

        # Initialize deque for this event type if needed
        if event not in self._rate_limit_timestamps:
            self._rate_limit_timestamps[event] = collections.deque(maxlen=max(max_per_minute, max_per_hour) + 10)

        timestamps = self._rate_limit_timestamps[event]

        # Prune stale timestamps (older than 1 hour)
        one_hour_ago = now - timedelta(hours=1)
        while timestamps and timestamps[0] < one_hour_ago:
            timestamps.popleft()

        # Check per-minute limit
        one_min_ago = now - timedelta(minutes=1)
        count_last_minute = sum(1 for t in timestamps if t > one_min_ago)
        if count_last_minute >= max_per_minute:
            return False

        # Check per-hour limit
        count_last_hour = len(timestamps)
        if count_last_hour >= max_per_hour:
            return False

        # Record this delivery timestamp
        timestamps.append(now)
        return True

    async def fire(
        self,
        event: str,
        payload: dict[str, Any],
        force: bool = False,
    ) -> WebhookDelivery | None:
        """Fire a webhook for the given event with payload.

        Args:
            event: The event type identifier.
            payload: The JSON-serializable payload to send.
            force: If True, bypass the event filter (used for test pings).

        Returns a WebhookDelivery record, or None if webhook is not configured/enabled.
        """
        if not force and not self.is_enabled_for(event):
            return None

        # Check rate limit before firing
        if not force and not self._check_rate_limit(event):
            delivery = WebhookDelivery(
                id=str(uuid.uuid4()),
                event=event,
                url=self._config.url,
                timestamp=datetime.now(timezone.utc).isoformat(),
                success=False,
                status_code=429,
                error=f"Rate limited: exceeded {self._config.rate_limit_max_per_minute}/min or {self._config.rate_limit_max_per_hour}/hr",
            )
            self._delivery_log.append(delivery)
            if len(self._delivery_log) > 100:
                self._delivery_log = self._delivery_log[-100:]
            return delivery

        import httpx

        delivery = WebhookDelivery(
            id=str(uuid.uuid4()),
            event=event,
            url=self._config.url,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Build payload with envelope
        body = {
            "event": event,
            "timestamp": delivery.timestamp,
            "delivery_id": delivery.id,
            "source": "sentinel-x-ultra",
            "data": payload,
        }

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Sentinel-X-Ultra-Webhook/1.0",
            "X-Webhook-Event": event,
            "X-Delivery-Id": delivery.id,
        }
        # Add custom headers from config
        headers.update(self._config.headers)

        # Add HMAC signature if secret is configured
        if self._config.secret:
            import hashlib
            import hmac
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            signature = hmac.new(
                self._config.secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Signature-256"] = f"sha256={signature}"

        # Fire with retries
        last_error = ""
        for attempt in range(self._config.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._config.timeout_seconds) as client:
                    response = await client.post(
                        self._config.url,
                        json=body,
                        headers=headers,
                    )
                    delivery.status_code = response.status_code
                    delivery.success = 200 <= response.status_code < 300
                    if delivery.success:
                        break
                    else:
                        last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            except httpx.TimeoutException:
                last_error = f"Timeout after {self._config.timeout_seconds}s (attempt {attempt + 1}/{self._config.max_retries})"
            except httpx.ConnectError:
                last_error = f"Connection refused (attempt {attempt + 1}/{self._config.max_retries})"
            except Exception as e:
                last_error = f"{type(e).__name__}: {e!s} (attempt {attempt + 1}/{self._config.max_retries})"

            if attempt < self._config.max_retries - 1:
                import asyncio
                await asyncio.sleep(1 * (attempt + 1))  # Exponential-ish backoff

        delivery.error = last_error

        # Truncate payload preview for log
        payload_str = json.dumps(payload, separators=(",", ":"))
        delivery.payload_preview = payload_str[:200] + ("..." if len(payload_str) > 200 else "")

        # Log delivery
        self._delivery_log.append(delivery)
        # Keep log bounded
        if len(self._delivery_log) > 100:
            self._delivery_log = self._delivery_log[-100:]

        return delivery

    async def fire_policy_decision(
        self,
        finding_title: str,
        finding_type: str,
        decision: str,
        confidence: float,
        compliance_score: int,
        scope_status: str,
        evidence_tier: str,
        impact_status: str,
        rejection_arguments: list[str],
        policy_citations: list[str],
        recommended_next_action: str,
        target: str = "",
        severity: str = "medium",
        **extra,
    ) -> WebhookDelivery | None:
        """Convenience method to fire a webhook for a policy decision."""
        payload = {
            "finding_title": finding_title,
            "finding_type": finding_type,
            "decision": decision,
            "confidence": confidence,
            "compliance_score": compliance_score,
            "scope_status": scope_status,
            "evidence_tier": evidence_tier,
            "impact_status": impact_status,
            "rejection_arguments": rejection_arguments,
            "policy_citations": policy_citations,
            "recommended_next_action": recommended_next_action,
            "target": target,
            "severity": severity,
            # Extra fields for richer context
            "is_critical": severity.lower() == "critical",
            "needs_review": decision == "REVIEW",
            "is_rejected": decision == "REJECT",
            "is_allowed": decision == "ALLOW",
        }
        return await self.fire(WEBHOOK_EVENT_POLICY_DECISION, payload)

    async def fire_pipeline_completed(
        self,
        pipeline_id: str,
        summary: dict[str, Any],
        policy_decisions: list[dict[str, Any]],
    ) -> WebhookDelivery | None:
        """Convenience method to fire a webhook for pipeline completion."""
        # Summarize decisions
        total = len(policy_decisions)
        allows = sum(1 for d in policy_decisions if d.get("decision") == "ALLOW")
        reviews = sum(1 for d in policy_decisions if d.get("decision") == "REVIEW")
        rejects = sum(1 for d in policy_decisions if d.get("decision") == "REJECT")

        payload = {
            "pipeline_id": pipeline_id,
            "total_findings": total,
            "allows": allows,
            "reviews": reviews,
            "rejects": rejects,
            "summary": summary,
            "decisions": [
                {
                    "finding_title": d.get("finding_title"),
                    "finding_type": d.get("finding_type"),
                    "decision": d.get("decision"),
                    "confidence": d.get("confidence"),
                    "compliance_score": d.get("compliance_score"),
                    "scope_status": d.get("scope_status"),
                    "evidence_tier": d.get("evidence_tier"),
                    "impact_status": d.get("impact_status"),
                }
                for d in policy_decisions
            ],
        }
        return await self.fire(WEBHOOK_EVENT_PIPELINE_COMPLETED, payload)

    async def test_webhook(self) -> WebhookDelivery:
        """Send a test ping to verify webhook configuration."""
        payload = {
            "test": True,
            "message": "This is a test webhook from Sentinel-X-Ultra Bug Bounty System",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.fire("test", payload, force=True)
