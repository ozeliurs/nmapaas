from ipaddress import ip_address

from fakeredis.aioredis import FakeRedis

from nmapaas.models import Scan, ScanCreate, ScanStatus
from nmapaas.store import ScanStore


async def test_scan_queue_and_lifecycle() -> None:
    redis = FakeRedis(decode_responses=True)
    store = ScanStore(redis, ttl_seconds=600)
    request = ScanCreate(target=ip_address("8.8.8.8"), location="us-east", profile="quick")
    scan = Scan.new(scan_id="scan-1", request=request)

    await store.create(scan)
    assert await store.next_scan("us-east", block_seconds=1) == "scan-1"

    running = await store.start("scan-1")
    assert running
    assert running.status == ScanStatus.RUNNING

    await store.progress("scan-1", 42.5)
    await store.finish_completed("scan-1", {"hosts": []})
    completed = await store.get("scan-1")
    assert completed
    assert completed.status == ScanStatus.COMPLETED
    assert completed.progress == 100
    assert completed.result == {"hosts": []}

    await redis.aclose()


async def test_queued_scan_can_be_cancelled() -> None:
    redis = FakeRedis(decode_responses=True)
    store = ScanStore(redis, ttl_seconds=600)
    request = ScanCreate(target=ip_address("8.8.8.8"), location="us-east")
    await store.create(Scan.new(scan_id="scan-2", request=request))

    cancelling = await store.request_cancel("scan-2")
    assert cancelling
    assert cancelling.status == ScanStatus.CANCELLING

    await store.next_scan("us-east", block_seconds=1)
    cancelled = await store.start("scan-2")
    assert cancelled
    assert cancelled.status == ScanStatus.CANCELLED
    await redis.aclose()
