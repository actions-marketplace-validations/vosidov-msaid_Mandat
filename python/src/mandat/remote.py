"""Guard <-> control plane clients (port of src/guard/remote.ts). Standard library only.

The data plane keeps working on its last snapshot when the control plane is down: policy from the
cache file, revocations marked stale (high-risk tools then fail closed). Polling and ledger shipping
run on daemon threads, never on the request path.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .policy import CompiledPolicy, compile_policy
from .revocation import match_revocation

__all__ = ["ControlPlane", "ControlPlaneError", "RemoteRevocations", "RemotePolicy", "FilePolicy", "StaticPolicy", "RemoteApprovals", "HttpLedger", "MemoryLedger", "now_iso"]


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

Log = Callable[[str], None]


def now_iso() -> str:
    """JavaScript Date#toISOString format, e.g. 2026-11-04T04:20:07.692Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ControlPlaneError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class ControlPlane:
    """Minimal JSON client for the Mandat control plane API."""

    def __init__(self, url: str, api_key: str, log: Log | None = None) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.log = log or (lambda m: None)

    def request(self, method: str, path: str, body: Any = None, timeout: float = 5, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any], dict[str, str]]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "authorization": f"Bearer {self.api_key}",
            **({"content-type": "application/json"} if data is not None else {}),
            **(headers or {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310 - URL comes from configuration
                text = res.read().decode()
                return res.status, (json.loads(text) if text else {}), dict(res.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, {}, dict(e.headers)
            text = e.read().decode(errors="replace")
            try:
                payload = json.loads(text)
                msg = payload.get("error_description") or payload.get("error") or text
            except ValueError:
                msg = text
            raise ControlPlaneError(e.code, f"{method} {path}: {e.code} {msg}") from None

    def call(self, method: str, path: str, body: Any = None, timeout: float = 5) -> dict[str, Any]:
        return self.request(method, path, body, timeout)[1]

    def rejected_key_message(self, status: int, consequence: str) -> str:
        return (f"Control plane {self.url} rejected this guard's API key (HTTP {status}); {consequence}. "
                "Use the service key from .mandat/credentials.json of the folder where `mandat serve` runs.")


class _Poller:
    def __init__(self, interval: float) -> None:
        self._stop = threading.Event()
        self._interval = interval
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.refresh()

    def refresh(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:
        self._stop.set()


class RemoteRevocations(_Poller):
    """Polls revocations every 2 s; `stale()` after 15 s without a successful refresh."""

    def __init__(self, cp: ControlPlane, interval: float = 2, stale_after: float = 15) -> None:
        super().__init__(interval)
        self.cp = cp
        self.stale_after = stale_after
        self._list: list[dict[str, Any]] = []
        self._last_ok = 0.0
        self._auth_warned = False

    def refresh(self) -> None:
        try:
            self._list = self.cp.call("GET", "/api/revocations", timeout=3)["revocations"]
            self._last_ok = time.monotonic()
            self._auth_warned = False
        except ControlPlaneError as e:
            if e.status in (401, 403) and not self._auth_warned:
                self._auth_warned = True
                self.cp.log(self.cp.rejected_key_message(e.status, "revocations cannot be refreshed, so financial and destructive tools fail closed"))
        except Exception:  # noqa: BLE001 - keep the last snapshot; stale() reports it
            pass

    def check(self, claims: dict[str, Any]) -> dict[str, Any] | None:
        return match_revocation(claims, self._list)

    def stale(self) -> bool:
        return time.monotonic() - self._last_ok > self.stale_after


class StaticPolicy:
    def __init__(self, policy: CompiledPolicy) -> None:
        self._policy = policy

    def current(self) -> CompiledPolicy:
        return self._policy


class FilePolicy(_Poller):
    """Local policy file, hot-reloaded on change. An invalid edit keeps the previous policy."""

    def __init__(self, path: str, log: Log | None = None, interval: float = 1) -> None:
        super().__init__(interval)
        self.path = path
        self.log = log or (lambda m: None)
        self._mtime = os.stat(path).st_mtime
        self._policy = compile_policy(_read_json(path))

    def refresh(self) -> None:
        try:
            mtime = os.stat(self.path).st_mtime
            if mtime != self._mtime:
                self._mtime = mtime
                self._policy = compile_policy(_read_json(self.path))
        except Exception as e:  # noqa: BLE001
            self.log(f"policy reload failed, keeping previous version: {e}")

    def current(self) -> CompiledPolicy:
        return self._policy


class RemotePolicy(_Poller):
    """Policy pulled from the control plane (ETag polling) with an on-disk snapshot for offline cold starts."""

    def __init__(self, cp: ControlPlane, snapshot_path: str | None = None, interval: float = 5) -> None:
        super().__init__(interval)
        self.cp = cp
        self.snapshot_path = snapshot_path
        self._etag: str | None = None
        self._policy: CompiledPolicy | None = None
        if snapshot_path and os.path.exists(snapshot_path):
            try:
                self._policy = compile_policy(_read_json(snapshot_path))
            except Exception:  # noqa: BLE001 - ignore a bad snapshot
                pass

    def refresh(self) -> None:
        try:
            status, body, headers = self.cp.request("GET", "/api/policy", timeout=3, headers={"if-none-match": self._etag} if self._etag else None)
            if status == 304:
                return
            self._policy = compile_policy(body["policy"])
            self._etag = headers.get("etag") or headers.get("ETag")
            if self.snapshot_path:
                os.makedirs(os.path.dirname(self.snapshot_path) or ".", exist_ok=True)
                tmp = f"{self.snapshot_path}.{os.getpid()}.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(body["policy"], f, indent=2)
                os.replace(tmp, self.snapshot_path)
        except Exception:  # noqa: BLE001 - keep the last snapshot
            pass

    def current(self) -> CompiledPolicy:
        if self._policy is None:
            raise RuntimeError("No policy available yet (control plane unreachable and no snapshot)")
        return self._policy


class RemoteApprovals:
    def __init__(self, cp: ControlPlane) -> None:
        self.cp = cp

    async def request(self, new_approval: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(self.cp.call, "POST", "/api/approvals", new_approval)

    async def wait(self, approval_id: str, timeout: float) -> dict[str, Any]:
        """Long-polls in <= 25 s slices until decided or `timeout` (seconds) elapses."""
        deadline = time.monotonic() + timeout
        while True:
            slice_ms = int(max(0, min(25, deadline - time.monotonic())) * 1000)
            cur = await asyncio.to_thread(self.cp.call, "GET", f"/api/approvals/{approval_id}?wait={slice_ms}", None, slice_ms / 1000 + 5)
            if cur["status"] != "pending" or time.monotonic() >= deadline:
                return cur

    async def consume(self, approval_id: str) -> bool:
        return bool((await asyncio.to_thread(self.cp.call, "POST", f"/api/approvals/{approval_id}/consume", {}))["consumed"])


class HttpLedger:
    """Ships records to the control plane ledger: batched, off the request path, at-least-once.

    Every record carries a client id, so the control plane de-duplicates retries.
    """

    def __init__(self, cp: ControlPlane, flush_interval: float = 0.5) -> None:
        self.cp = cp
        self._queue: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._auth_warned = False
        self.last_error: str | None = None
        self._interval = flush_interval
        threading.Thread(target=self._loop, daemon=True).start()

    def append(self, record: dict[str, Any]) -> None:
        rec = {"id": f"rec_{uuid.uuid4()}", "ts": now_iso(), **record}
        with self._lock:
            self._queue.append(rec)
            if len(self._queue) > 100_000:
                self._queue.pop(0)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.flush()

    def flush(self) -> None:
        with self._flush_lock:
            try:
                while True:
                    with self._lock:
                        batch = self._queue[:200]
                    if not batch:
                        break
                    self.cp.call("POST", "/api/ledger/ingest", {"records": batch})
                    with self._lock:
                        del self._queue[: len(batch)]
                self.last_error = None
                self._auth_warned = False
            except ControlPlaneError as e:
                self.last_error = str(e)
                if e.status in (401, 403) and not self._auth_warned:
                    self._auth_warned = True
                    self.cp.log(self.cp.rejected_key_message(e.status, f"{len(self._queue)} audit records are queued and not delivered"))
            except Exception as e:  # noqa: BLE001 - retried on the next tick
                self.last_error = str(e)

    async def aflush(self) -> None:
        await asyncio.to_thread(self.flush)

    @property
    def pending(self) -> int:
        return len(self._queue)

    def close(self) -> None:
        self._stop.set()
        self.flush()


class MemoryLedger:
    """In-memory sink for tests and local experiments."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def append(self, record: dict[str, Any]) -> None:
        self.records.append({"id": f"rec_{uuid.uuid4()}", "ts": now_iso(), **record})

    def flush(self) -> None:
        pass

    async def aflush(self) -> None:
        pass
