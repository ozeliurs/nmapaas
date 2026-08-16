from functools import cached_property, lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from nmapaas.vpn import VPNSpec


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    redis_url: str = "redis://localhost:6379/0"
    api_key: str = ""
    locations: str = "local"
    worker_concurrency: int = Field(default=2, ge=1, le=32)
    job_ttl_seconds: int = Field(default=86_400, ge=60)
    scan_timeout_seconds: int = Field(default=3_600, ge=10)
    allow_private_targets: bool = False
    allowed_target_cidrs: str = ""
    vpn_config_dir: str = "/etc/vpn"

    @cached_property
    def location_specs(self) -> dict[str, VPNSpec | None]:
        """Parse LOCATIONS entries of the form ``name`` or ``name:a.b.c``.

        Each name becomes a scan queue. An entry with a subnet additionally
        gets a WireGuard namespace ``vpn-<name>``, a /24 veth pair on
        ``a.b.c.0/24``, and a config at ``<vpn_config_dir>/<name>.conf``.
        Entries without a subnet (``None``) run scans directly, without a VPN.
        """
        specs: dict[str, VPNSpec | None] = {}
        for entry in self.locations.split(","):
            entry = entry.strip()
            if not entry:
                continue
            name, separator, subnet = entry.partition(":")
            name = name.strip()
            subnet = subnet.strip()
            if not name:
                raise ValueError(f"invalid LOCATIONS entry {entry!r}: empty name")
            if name in specs:
                raise ValueError(f"duplicate LOCATIONS entry {name!r}")
            if not separator:
                specs[name] = None
                continue
            if not subnet:
                raise ValueError(
                    f"invalid LOCATIONS entry {entry!r}: expected 'name:a.b.c'"
                )
            config_path = f"{self.vpn_config_dir.rstrip('/')}/{name}.conf"
            if len(Path(config_path).stem) > 15:
                raise ValueError(
                    f"invalid LOCATIONS entry {entry!r}: config basename must be at "
                    "most 15 characters (kernel interface name limit)"
                )
            specs[name] = VPNSpec(name=name, subnet=subnet, config_path=config_path)
        return specs

    @cached_property
    def location_names(self) -> set[str]:
        """All configured location names, VPN-backed or not."""
        return set(self.location_specs)

    @cached_property
    def vpn_specs(self) -> dict[str, VPNSpec]:
        """The subset of locations that have a WireGuard namespace."""
        return {name: spec for name, spec in self.location_specs.items() if spec is not None}

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
