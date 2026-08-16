"""In-process scan consumer.

Network namespaces and WireGuard tunnels are set up once by the
``nmapaas-netns`` init container; this module only executes scans inside the
existing namespaces via ``ip netns exec``.
"""

import asyncio
import logging
from functools import partial

from redis.asyncio import Redis

from nmapaas.config import Settings
from nmapaas.models import Scan, ScanStatus
from nmapaas.scanner import ScanCancelledError, ScanExecutionError, run_scan
from nmapaas.store import ScanStore
from nmapaas.vpn import NamespaceManager, VPNSpec

logger = logging.getLogger(__name__)


async def execute_scan(
    scan: Scan,
    spec: VPNSpec | None,
    store: ScanStore,
    settings: Settings,
    semaphore: asyncio.Semaphore,
) -> None:
    try:
        result = await run_scan(
            scan.target,
            scan.profile,
            timeout_seconds=settings.scan_timeout_seconds,
            on_progress=partial(store.progress, scan.id),
            should_cancel=partial(store.is_cancelling, scan.id),
            namespace=spec.namespace if spec else None,
        )
    except ScanCancelledError:
        await store.finish_cancelled(scan.id)
    except (ScanExecutionError, OSError) as exc:
        await store.finish_failed(scan.id, str(exc))
        logger.warning("failed scan %s: %s", scan.id, exc)
    except Exception:
        await store.finish_failed(scan.id, "unexpected worker error")
        logger.exception("unexpected failure for scan %s", scan.id)
    else:
        await store.finish_completed(scan.id, result)
    finally:
        semaphore.release()


async def consume_location(
    location: str,
    spec: VPNSpec | None,
    store: ScanStore,
    settings: Settings,
    manager: NamespaceManager,
) -> None:
    semaphore = asyncio.Semaphore(settings.worker_concurrency)
    tasks: set[asyncio.Task[None]] = set()
    logger.info(
        "consuming location %s%s",
        location,
        f" via namespace {spec.namespace}" if spec else " without a VPN namespace",
    )
    while True:
        scan_id = await store.next_scan(location)
        if scan_id is None:
            continue
        scan = await store.start(scan_id)
        if scan is None or scan.status == ScanStatus.CANCELLED:
            continue
        if spec is not None and not await manager.namespace_exists(spec):
            await store.finish_failed(
                scan.id, f"VPN namespace {spec.namespace} is not running"
            )
            continue
        await semaphore.acquire()
        task = asyncio.create_task(execute_scan(scan, spec, store, settings, semaphore))
        tasks.add(task)
        task.add_done_callback(tasks.discard)


async def consume_forever(redis: Redis, settings: Settings) -> None:
    """Consume every configured location queue until cancelled."""
    store = ScanStore(redis, settings.job_ttl_seconds)
    manager = NamespaceManager(settings.vpn_specs)
    async with asyncio.TaskGroup() as group:
        for location in sorted(settings.location_names):
            group.create_task(
                consume_location(
                    location, settings.vpn_specs.get(location), store, settings, manager
                )
            )
