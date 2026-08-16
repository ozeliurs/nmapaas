from ipaddress import ip_address

from fakeredis.aioredis import FakeRedis

from nmapaas.api import create_scan
from nmapaas.config import Settings
from nmapaas.models import ScanCreate
from nmapaas.store import ScanStore


async def test_default_location_uses_least_loaded_worker() -> None:
    redis = FakeRedis(decode_responses=True)
    store = ScanStore(redis, ttl_seconds=600)
    settings = Settings(locations="marseille-france,netherlands")
    marseille_request = ScanCreate(
        target=ip_address("8.8.8.8"), location="marseille-france"
    )
    await create_scan(marseille_request, settings, store)

    scan = await create_scan(ScanCreate(target=ip_address("8.8.4.4")), settings, store)

    assert scan.location == "netherlands"
    await redis.aclose()
