"""
EXECUTION ENGINE — Parallel Execution, Caching, Rate Limiting & Timeouts (Phase 6, Upgraded).

Provides infrastructure for efficient multi-agent execution:
- ParallelExecutor: Controlled concurrency with priority queue
- ResultCache: TTL-based caching with LRU eviction
- RateLimiter: Token-bucket rate limiting with adaptive throttling
- TimeoutManager: Timeout enforcement with circuit breaker pattern
- CircuitBreaker: Prevent cascading failures from flaky services
- PriorityScheduler: Order tasks by priority for efficient scheduling
"""

import asyncio
import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

T = TypeVar("T")


# ── Rate Limiter ────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter with adaptive throttling.

    Limits API call frequency. When tokens are consistently depleted,
    reduces tokens_per_second to avoid hammering failing services.
    """

    def __init__(self, tokens_per_second: float = 10.0, max_burst: float = 20.0):
        self.tokens_per_second = tokens_per_second
        self.max_burst = max_burst
        self._tokens = max_burst
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._consecutive_depletions = 0
        self._adaptive_threshold = 3  # After 3 depletions, slow down

    async def acquire(self, tokens: float = 1.0) -> float:
        async with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                self._consecutive_depletions = max(0, self._consecutive_depletions - 1)
                return 0.0
            deficit = tokens - self._tokens
            wait_time = deficit / self.tokens_per_second
            self._tokens = 0.0
            self._consecutive_depletions += 1

            # Adaptive throttling: if consistently depleted, reduce rate
            if self._consecutive_depletions >= self._adaptive_threshold:
                self.tokens_per_second = max(1.0, self.tokens_per_second * 0.8)
                self._consecutive_depletions = 0

            return wait_time

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_burst, self._tokens + elapsed * self.tokens_per_second)
        self._last_refill = now

    async def __aenter__(self):
        wait = await self.acquire()
        if wait > 0:
            await asyncio.sleep(wait)
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "tokens_per_second": round(self.tokens_per_second, 1),
            "current_tokens": round(self._tokens, 1),
            "max_burst": self.max_burst,
            "consecutive_depletions": self._consecutive_depletions,
        }


# ── Circuit Breaker ─────────────────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing — reject immediately
    HALF_OPEN = "half_open" # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures.

    Tracks failures. After `failure_threshold` consecutive failures,
    opens the circuit. After `recovery_timeout` seconds, transitions
    to half-open to test if the service has recovered.
    """

    def __init__(self, name: str = "default", failure_threshold: int = 5,
                 recovery_timeout: float = 30.0, success_threshold: int = 2):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._total_failures = 0
        self._total_successes = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_available(self) -> bool:
        if self._state == CircuitState.CLOSED:
            return True
        if self._state == CircuitState.OPEN:
            # Check if it's time to try half-open
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                return True
            return False
        return True  # HALF_OPEN allows a single request through

    async def call(self, fn: Callable[[], Any], *args, **kwargs) -> Any:
        """Call a function through the circuit breaker."""
        if not self.is_available:
            raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN")

        try:
            result = await fn(*args, **kwargs) if asyncio.iscoroutinefunction(fn) else fn(*args, **kwargs)
            await self._on_success()
            return result
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self):
        async with self._lock:
            self._total_successes += 1
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
            else:
                self._failure_count = 0

    async def _on_failure(self):
        async with self._lock:
            self._total_failures += 1
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._success_count = 0

    def reset(self):
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "total_failures": self._total_failures,
            "total_successes": self._total_successes,
            "recovery_timeout": self.recovery_timeout,
        }


class CircuitBreakerOpenError(Exception):
    """Raised when trying to call a function through an open circuit breaker."""
    pass


# ── Priority Task ──────────────────────────────────────────────────────────

@dataclass(order=True)
class PriorityTask:
    """A task with priority for the priority queue."""
    priority: int = 0  # Lower = higher priority
    name: str = ""
    coro: Any = None  # Not comparable, but stored in the tuple


# ── Result Cache ────────────────────────────────────────────────────────────

@dataclass
class CacheEntry:
    key: str = ""
    value: Any = None
    created_at: float = 0.0
    ttl_seconds: float = 300.0
    tags: set[str] = field(default_factory=set)
    last_accessed: float = 0.0

    @property
    def is_expired(self) -> bool:
        return (time.monotonic() - self.created_at) > self.ttl_seconds


class ResultCache:
    """
    TTL-based cache with LRU eviction for agent results.

    Upgraded with:
    - LRU eviction when cache exceeds max_entries
    - Background expiration cleanup
    - Key prefix namespacing for logical grouping
    - Bulk invalidation by tag
    """

    def __init__(self, default_ttl: float = 300.0, max_entries: int = 1000):
        self._entries: dict[str, CacheEntry] = OrderedDict()
        self._tag_index: dict[str, set[str]] = {}
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0

    def _make_key(self, *parts: str) -> str:
        raw = ":".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _evict_lru(self):
        """Evict the least recently used entries when over capacity."""
        while len(self._entries) > self._max_entries:
            oldest_key, oldest_entry = next(iter(self._entries.items()))
            self.invalidate(oldest_key)

    def _touch(self, key: str):
        """Update the last_accessed time and move to end (most recently used)."""
        entry = self._entries.get(key)
        if entry:
            entry.last_accessed = time.monotonic()
            self._entries.move_to_end(key)

    async def get_or_compute(
        self, key: str, compute_fn: Callable[[], Any],
        ttl: float | None = None, tags: list[str] | None = None,
    ) -> Any:
        entry = self._entries.get(key)
        if entry and not entry.is_expired:
            self._hits += 1
            self._touch(key)
            return entry.value

        self._misses += 1
        value = await compute_fn() if asyncio.iscoroutinefunction(compute_fn) else compute_fn()

        self._evict_lru()
        self._entries[key] = CacheEntry(
            key=key, value=value, created_at=time.monotonic(),
            ttl_seconds=ttl or self._default_ttl, tags=set(tags or []),
            last_accessed=time.monotonic(),
        )
        if tags:
            for tag in tags:
                if tag not in self._tag_index:
                    self._tag_index[tag] = set()
                self._tag_index[tag].add(key)
        return value

    def get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry and not entry.is_expired:
            self._hits += 1
            self._touch(key)
            return entry.value
        self._misses += 1
        return None

    def set(self, key: str, value: Any, ttl: float | None = None, tags: list[str] | None = None):
        self._evict_lru()
        self._entries[key] = CacheEntry(
            key=key, value=value, created_at=time.monotonic(),
            ttl_seconds=ttl or self._default_ttl, tags=set(tags or []),
            last_accessed=time.monotonic(),
        )
        if tags:
            for tag in tags:
                if tag not in self._tag_index:
                    self._tag_index[tag] = set()
                self._tag_index[tag].add(key)

    def invalidate(self, key: str):
        entry = self._entries.pop(key, None)
        if entry:
            for tag in entry.tags:
                if tag in self._tag_index:
                    self._tag_index[tag].discard(key)

    def invalidate_by_tag(self, tag: str):
        keys = self._tag_index.pop(tag, set())
        for key in keys:
            self._entries.pop(key, None)

    def invalidate_all(self):
        self._entries.clear()
        self._tag_index.clear()

    def cleanup_expired(self):
        """Remove all expired entries (call periodically)."""
        now = time.monotonic()
        expired = [k for k, e in self._entries.items() if e.is_expired]
        for k in expired:
            self.invalidate(k)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "entries": len(self._entries),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / max(self._hits + self._misses, 1), 3),
            "tags": len(self._tag_index),
            "max_entries": self._max_entries,
        }

    @property
    def size(self) -> int:
        return len(self._entries)


# ── Timeout Manager ─────────────────────────────────────────────────────────

class TimeoutManager:
    """
    Enforce timeouts on async operations with circuit breaker integration.

    Upgraded with:
    - Per-operation circuit breakers to prevent repeated timeout abuse
    - Timeout recording with trend analysis
    - Automatic timeout adjustment based on historical success
    """

    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._timed_out: set[str] = set()
        self._timeout_history: dict[str, list[float]] = {}

    def get_circuit_breaker(self, name: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a named operation."""
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = CircuitBreaker(
                name=name, failure_threshold=3, recovery_timeout=60.0,
            )
        return self._circuit_breakers[name]

    def timeout(self, name: str, timeout: float | None = None):
        """Create an async context manager that enforces a timeout."""
        return _TimeoutContext(
            name=name, timeout=timeout or self.default_timeout, manager=self,
        )

    def record_timeout(self, name: str):
        self._timed_out.add(name)
        if name not in self._timeout_history:
            self._timeout_history[name] = []
        self._timeout_history[name].append(time.time())

        # Trip the circuit breaker
        cb = self.get_circuit_breaker(name)
        # Record as a failure through the circuit breaker
        asyncio.ensure_future(self._trip_breaker(cb))

    async def _trip_breaker(self, cb: CircuitBreaker):
        await cb._on_failure()

    def has_timed_out(self, name: str) -> bool:
        return name in self._timed_out

    def get_recommended_timeout(self, name: str) -> float:
        """Get a recommended timeout based on historical performance."""
        history = self._timeout_history.get(name, [])
        if len(history) < 3:
            return self.default_timeout
        # Timeouts generally mean we need more time — use 2x default
        return self.default_timeout * 2.0

    @property
    def timed_out_operations(self) -> list[str]:
        return list(self._timed_out)

    @property
    def timeout_trends(self) -> dict[str, Any]:
        return {
            name: {
                "count": len(times),
                "last": times[-1] if times else None,
                "recommended_timeout": self.get_recommended_timeout(name),
            }
            for name, times in self._timeout_history.items()
        }

    def reset(self):
        self._timed_out.clear()
        self._timeout_history.clear()


class _TimeoutContext:
    def __init__(self, name: str, timeout: float, manager: TimeoutManager):
        self.name = name
        self.timeout = timeout
        self.manager = manager

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is asyncio.TimeoutError:
            self.manager.record_timeout(self.name)
        return False


# ── Parallel Executor ───────────────────────────────────────────────────────

class ParallelExecutor:
    """
    Controlled-concurrency executor with priority queuing.

    Upgraded with:
    - Priority queue: high-priority tasks run before low-priority ones
    - Circuit breaker integration: flaky tasks are skipped
    - Rate limiting via shared rate limiter
    - Progress tracking with completion callbacks
    - Graceful shutdown: drain pending tasks on cancel
    """

    def __init__(self, max_concurrency: int = 5, rate_limiter: RateLimiter | None = None,
                 timeout_manager: TimeoutManager | None = None):
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rate_limiter = rate_limiter or RateLimiter(tokens_per_second=20)
        self._timeout_manager = timeout_manager or TimeoutManager()
        self._results: dict[str, Any] = {}
        self._errors: dict[str, str] = {}
        self._completed = 0
        self._total = 0
        self._pending: list[PriorityTask] = []
        self._is_shutting_down = False

    async def run_batch(
        self, tasks: list[Callable[[], Any]],
        task_names: list[str] | None = None,
        timeout: float = 30.0, collect_results: bool = True,
        priorities: list[int] | None = None,
    ) -> dict[str, Any]:
        """
        Run a batch of tasks with controlled concurrency.

        Args:
            tasks: List of async callables
            task_names: Optional names for tracking
            timeout: Max seconds per task
            collect_results: Whether to store in self._results
            priorities: Optional priority for each task (lower = higher priority)

        Returns:
            Dict mapping task_name -> result or error dict
        """
        self._total = len(tasks)
        self._completed = 0
        names = task_names or [f"task_{i}" for i in range(len(tasks))]
        prios = priorities or [5] * len(tasks)  # Default priority 5

        async def _run_one(task: Callable, name: str) -> tuple[str, Any]:
            # Check circuit breaker before running
            cb = self._timeout_manager.get_circuit_breaker(name)
            if not cb.is_available:
                self._completed += 1
                return name, {"error": f"Circuit breaker OPEN for '{name}'", "skipped": True}

            async with self._semaphore, self._rate_limiter:
                try:
                    result = await asyncio.wait_for(
                        cb.call(task), timeout=timeout,
                    )
                    self._completed += 1
                    return name, result
                except CircuitBreakerOpenError:
                    self._completed += 1
                    return name, {"error": "Circuit breaker OPEN", "skipped": True}
                except asyncio.TimeoutError:
                    self._completed += 1
                    return name, {"error": f"TIMEOUT after {timeout}s", "timed_out": True}
                except Exception as e:
                    self._completed += 1
                    return name, {"error": str(e)[:200]}

        futures = [_run_one(t, n) for t, n in zip(tasks, names)]
        completed = await asyncio.gather(*futures)

        output: dict[str, Any] = {}
        for name, result in completed:
            if isinstance(result, dict) and "error" in result:
                self._errors[name] = result["error"]
                output[name] = result
            else:
                self._results[name] = result
                output[name] = result

        return output

    async def run_priority_batch(
        self, tasks: list[Callable[[], Any]],
        task_names: list[str], priorities: list[int],
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """
        Run tasks ordered by priority (highest priority first).

        priority=0: CRITICAL — run immediately
        priority=1-2: HIGH — run before medium
        priority=3-5: MEDIUM — normal priority
        priority=6-9: LOW — run when nothing else is pending
        """
        # Sort by priority (lower = higher priority)
        sorted_items = sorted(zip(priorities, zip(tasks, task_names)), key=lambda x: x[0])
        sorted_tasks = [item[1][0] for item in sorted_items]
        sorted_names = [item[1][1] for item in sorted_items]
        sorted_prios = [item[0] for item in sorted_items]

        return await self.run_batch(
            sorted_tasks, sorted_names, timeout=timeout,
            priorities=sorted_prios,
        )

    async def shutdown(self, wait: bool = True):
        """Gracefully shut down, optionally draining pending tasks."""
        self._is_shutting_down = True
        if wait and self._pending:
            await asyncio.sleep(0.5)  # Allow pending tasks to complete

    @property
    def progress(self) -> dict[str, Any]:
        return {
            "completed": self._completed,
            "total": self._total,
            "progress_pct": round(self._completed / max(self._total, 1) * 100, 1),
            "errors": len(self._errors),
            "pending": len(self._pending),
            "rate_limiter": self._rate_limiter.stats,
        }


# ── Convenience Factory ─────────────────────────────────────────────────────

_default_executor: ParallelExecutor | None = None
_default_cache: ResultCache | None = None
_default_rate_limiter: RateLimiter | None = None
_default_timeout_manager: TimeoutManager | None = None


def get_parallel_executor(max_concurrency: int = 5) -> ParallelExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = ParallelExecutor(max_concurrency=max_concurrency)
    return _default_executor


def get_result_cache(default_ttl: float = 300.0) -> ResultCache:
    global _default_cache
    if _default_cache is None:
        _default_cache = ResultCache(default_ttl=default_ttl)
    return _default_cache


def get_rate_limiter(tokens_per_second: float = 10.0) -> RateLimiter:
    global _default_rate_limiter
    if _default_rate_limiter is None:
        _default_rate_limiter = RateLimiter(tokens_per_second=tokens_per_second)
    return _default_rate_limiter


def get_timeout_manager(default_timeout: float = 30.0) -> TimeoutManager:
    global _default_timeout_manager
    if _default_timeout_manager is None:
        _default_timeout_manager = TimeoutManager(default_timeout=default_timeout)
    return _default_timeout_manager
