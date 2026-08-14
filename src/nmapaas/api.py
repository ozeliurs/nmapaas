import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis

from nmapaas.config import Settings, get_settings
from nmapaas.models import Scan, ScanCreate
from nmapaas.store import ScanStore


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    await redis.ping()
    app.state.redis = redis
    app.state.store = ScanStore(redis, settings.job_ttl_seconds)
    yield
    await redis.aclose()


app = FastAPI(title="Nmap as a Service", version="0.1.0", lifespan=lifespan)
bearer_scheme = HTTPBearer(auto_error=False)


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
) -> None:
    if not settings.api_key:
        return
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not secrets.compare_digest(credentials.credentials, settings.api_key)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")


def get_store(request: Request) -> ScanStore:
    return request.app.state.store


def validate_target(request: ScanCreate, settings: Settings) -> None:
    target = ip_address(str(request.target))
    if settings.target_networks and not any(
        target in network for network in settings.target_networks
    ):
        raise HTTPException(status_code=422, detail="target is outside allowed CIDRs")
    unsafe = (
        target.is_private
        or target.is_loopback
        or target.is_link_local
        or target.is_multicast
        or target.is_reserved
        or target.is_unspecified
    )
    if unsafe and not settings.allow_private_targets:
        raise HTTPException(status_code=422, detail="non-public targets are disabled")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/healthz", include_in_schema=False)
async def health(request: Request) -> dict[str, str]:
    await request.app.state.redis.ping()
    return {"status": "ok"}


@app.get("/v1/locations", dependencies=[Depends(require_api_key)])
async def get_locations(
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict[str, str]]:
    return [{"name": "default", "type": "least-loaded"}] + [
        {"name": location, "type": "wireguard"} for location in sorted(settings.locations)
    ]


@app.post(
    "/v1/scans",
    response_model=Scan,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key)],
)
async def create_scan(
    body: ScanCreate,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[ScanStore, Depends(get_store)],
) -> Scan:
    if not settings.locations:
        raise HTTPException(status_code=503, detail="no scan locations configured")
    if body.location == "default":
        location = await store.least_loaded_location(settings.locations)
    elif body.location in settings.locations:
        location = body.location
    else:
        raise HTTPException(status_code=422, detail="unsupported scan location")
    validate_target(body, settings)
    scan = Scan.new(
        scan_id=str(uuid4()), request=body.model_copy(update={"location": location})
    )
    await store.create(scan)
    return scan


@app.get(
    "/v1/scans/{scan_id}",
    response_model=Scan,
    dependencies=[Depends(require_api_key)],
)
async def get_scan(
    scan_id: str, store: Annotated[ScanStore, Depends(get_store)]
) -> Scan:
    scan = await store.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@app.delete(
    "/v1/scans/{scan_id}",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key)],
)
async def cancel_scan(
    scan_id: str, store: Annotated[ScanStore, Depends(get_store)]
) -> Response:
    scan = await store.request_cancel(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return Response(status_code=status.HTTP_202_ACCEPTED)
