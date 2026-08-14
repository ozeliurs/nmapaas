from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import WatchError

from nmapaas.models import Scan, ScanStatus


class ScanStore:
    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self.redis = redis
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"nmapaas:scan:{scan_id}"

    @staticmethod
    def _queue(location: str) -> str:
        return f"nmapaas:queue:{location}"

    async def create(self, scan: Scan) -> None:
        async with self.redis.pipeline(transaction=True) as pipeline:
            pipeline.set(self._key(scan.id), scan.model_dump_json(), ex=self.ttl_seconds)
            pipeline.rpush(self._queue(scan.location), scan.id)
            await pipeline.execute()

    async def get(self, scan_id: str) -> Scan | None:
        raw = await self.redis.get(self._key(scan_id))
        return Scan.model_validate_json(raw) if raw else None

    async def update(self, scan_id: str, **changes: Any) -> Scan | None:
        key = self._key(scan_id)
        async with self.redis.pipeline(transaction=True) as pipeline:
            while True:
                try:
                    await pipeline.watch(key)
                    raw = await pipeline.get(key)
                    if not raw:
                        await pipeline.reset()
                        return None
                    scan = Scan.model_validate_json(raw).model_copy(update=changes)
                    pipeline.multi()
                    pipeline.set(key, scan.model_dump_json(), ex=self.ttl_seconds)
                    await pipeline.execute()
                    return scan
                except WatchError:
                    continue

    async def request_cancel(self, scan_id: str) -> Scan | None:
        scan = await self.get(scan_id)
        if scan and scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
            return await self.update(scan_id, status=ScanStatus.CANCELLING)
        return scan

    async def is_cancelling(self, scan_id: str) -> bool:
        scan = await self.get(scan_id)
        return scan is None or scan.status == ScanStatus.CANCELLING

    async def next_scan(self, location: str, block_seconds: int = 5) -> str | None:
        item = await self.redis.blpop(self._queue(location), timeout=block_seconds)
        return item[1] if item else None

    async def start(self, scan_id: str) -> Scan | None:
        scan = await self.get(scan_id)
        if scan is None:
            return None
        if scan.status == ScanStatus.CANCELLING:
            return await self.finish_cancelled(scan_id)
        if scan.status != ScanStatus.QUEUED:
            return None
        return await self.update(
            scan_id, status=ScanStatus.RUNNING, started_at=datetime.now(UTC)
        )

    async def progress(self, scan_id: str, value: float) -> None:
        scan = await self.get(scan_id)
        if scan and scan.status == ScanStatus.RUNNING and value > scan.progress:
            await self.update(scan_id, progress=min(value, 99.9))

    async def finish_completed(self, scan_id: str, result: dict[str, Any]) -> None:
        await self.update(
            scan_id,
            status=ScanStatus.COMPLETED,
            progress=100,
            result=result,
            completed_at=datetime.now(UTC),
        )

    async def finish_failed(self, scan_id: str, error: str) -> None:
        await self.update(
            scan_id,
            status=ScanStatus.FAILED,
            error=error,
            completed_at=datetime.now(UTC),
        )

    async def finish_cancelled(self, scan_id: str) -> Scan | None:
        return await self.update(
            scan_id,
            status=ScanStatus.CANCELLED,
            completed_at=datetime.now(UTC),
        )
