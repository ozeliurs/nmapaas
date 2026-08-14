from functools import cached_property, lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    redis_url: str = "redis://localhost:6379/0"
    api_key: str = ""
    scan_locations: str = "local"
    scan_location: str = "local"
    worker_concurrency: int = Field(default=2, ge=1, le=32)
    job_ttl_seconds: int = Field(default=86_400, ge=60)
    scan_timeout_seconds: int = Field(default=3_600, ge=10)
    allow_private_targets: bool = False
    allowed_target_cidrs: str = ""
    vpn_ready_file: str = ""

    @cached_property
    def locations(self) -> set[str]:
        return {location.strip() for location in self.scan_locations.split(",") if location.strip()}

    @cached_property
    def target_networks(self) -> list[IPv4Network | IPv6Network]:
        return [
            ip_network(value.strip())
            for value in self.allowed_target_cidrs.split(",")
            if value.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
