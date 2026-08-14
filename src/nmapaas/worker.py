import asyncio
import logging
from functools import partial
from urllib.request import urlopen

from redis.asyncio import Redis

from nmapaas.config import get_settings
from nmapaas.models import ScanStatus
from nmapaas.scanner import ScanCancelledError, ScanExecutionError, run_scan
from nmapaas.store import ScanStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def wait_for_vpn(url: str) -> None:
    if not url:
        return
    while True:
        try:
            response = await asyncio.to_thread(urlopen, url, timeout=2)
            response.close()
            logger.info("VPN is healthy")
            return
        except OSError:
            logger.warning("waiting for VPN")
            await asyncio.sleep(2)


async def process_scans(worker_number: int, store: ScanStore) -> None:
    settings = get_settings()
    logger.info("worker %d consuming location %s", worker_number, settings.scan_location)
    while True:
        scan_id = await store.next_scan(settings.scan_location)
        if scan_id is None:
            continue
        scan = await store.start(scan_id)
        if scan is None or scan.status == ScanStatus.CANCELLED:
            continue
        logger.info("starting scan %s", scan.id)
        try:
            result = await run_scan(
                scan.target,
                scan.profile,
                timeout_seconds=settings.scan_timeout_seconds,
                on_progress=partial(store.progress, scan.id),
                should_cancel=partial(store.is_cancelling, scan.id),
            )
        except ScanCancelledError:
            await store.finish_cancelled(scan.id)
            logger.info("cancelled scan %s", scan.id)
        except (ScanExecutionError, OSError) as exc:
            await store.finish_failed(scan.id, str(exc))
            logger.warning("failed scan %s: %s", scan.id, exc)
        except Exception:
            await store.finish_failed(scan.id, "unexpected worker error")
            logger.exception("unexpected failure for scan %s", scan.id)
        else:
            await store.finish_completed(scan.id, result)
            logger.info("completed scan %s", scan.id)


async def run() -> None:
    settings = get_settings()
    await wait_for_vpn(settings.vpn_health_url)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    while True:
        try:
            await redis.ping()
            break
        except Exception:
            logger.warning("waiting for Redis")
            await asyncio.sleep(2)
    store = ScanStore(redis, settings.job_ttl_seconds)
    try:
        async with asyncio.TaskGroup() as group:
            for number in range(1, settings.worker_concurrency + 1):
                group.create_task(process_scans(number, store))
    finally:
        await redis.aclose()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
