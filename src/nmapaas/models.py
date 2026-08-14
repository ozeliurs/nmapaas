from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanCreate(BaseModel):
    target: IPv4Address | IPv6Address
    location: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    profile: ScanProfile = ScanProfile.STANDARD


class Scan(BaseModel):
    id: str
    target: str
    location: str
    profile: ScanProfile
    status: ScanStatus
    progress: float = Field(ge=0, le=100)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result: dict[str, Any] | None = None

    @classmethod
    def new(cls, *, scan_id: str, request: ScanCreate) -> "Scan":
        return cls(
            id=scan_id,
            target=str(request.target),
            location=request.location,
            profile=request.profile,
            status=ScanStatus.QUEUED,
            progress=0,
            created_at=datetime.now(UTC),
        )
