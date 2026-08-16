import argparse
import asyncio
import logging
import shutil
import socket
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VPNSpec:
    """A WireGuard tunnel isolated in its own network namespace."""

    name: str
    subnet: str
    config_path: str

    @property
    def namespace(self) -> str:
        return f"vpn-{self.name}"

    @property
    def host_ip(self) -> str:
        return f"{self.subnet}.1/24"

    @property
    def ns_ip(self) -> str:
        return f"{self.subnet}.2/24"

    @property
    def gateway(self) -> str:
        return f"{self.subnet}.1"

    @property
    def veth_host(self) -> str:
        # Interface names are limited to 15 characters.
        return f"veth-{self.name}"[:15]

    @property
    def veth_ns(self) -> str:
        # Temporary name for the namespace end of the pair, renamed to eth0
        # after being moved into the namespace. Must differ from eth0 because
        # both ends are created in the caller's own namespace first, where the
        # container already has an eth0.
        return f"vethp-{self.name}"[:15]

    @property
    def interface(self) -> str:
        # The WireGuard interface takes the config file's basename.
        return Path(self.config_path).stem


def _config_value(text: str, wanted: str) -> str | None:
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().lower() == wanted:
            return value.strip()
    return None


def interface_address(text: str) -> str:
    """Extract the interface Address (with prefix) from a WireGuard config."""
    value = _config_value(text, "address")
    if not value:
        raise ValueError("WireGuard config has no Address")
    return value.split(",")[0].strip()


def strip_dns(config_text: str) -> str:
    """Remove wg-quick DNS directives.

    wg-quick fails when a DNS line is present but resolvconf is not
    installed, and scans only use literal IPs, so DNS inside the tunnel is
    pointless.
    """
    lines = [
        line
        for line in config_text.splitlines()
        if line.partition("=")[0].strip().lower() != "dns"
    ]
    return "\n".join(lines) + "\n"


def endpoint_host(config_text: str) -> str:
    """Extract the WireGuard endpoint host (hostname or IP)."""
    for line in config_text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().lower() == "endpoint":
            host = value.strip().rsplit(":", 1)[0]
            return host.strip("[]")
    raise ValueError("WireGuard config has no Endpoint")


def endpoint_port(config_text: str) -> int:
    """Extract the WireGuard endpoint port (default 51820)."""
    for line in config_text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().lower() == "endpoint":
            return int(value.strip().rstrip("]").rsplit(":", 1)[-1])
    return 51820


def _resolve(host: str) -> str:
    """Resolve a hostname to a literal IP; pass literal IPs through."""
    return socket.getaddrinfo(host, None)[0][4][0]


def prepare_config(text: str, endpoint_ip: str) -> str:
    """Sanitize a WireGuard config for use inside a namespace.

    - DNS directives are stripped (no resolvconf in the image, and scans
      only use literal IPs).
    - The Endpoint hostname is replaced with a literal IP resolved in the
      caller's namespace, since the target namespace has no DNS.
    - ``Table`` entries are dropped; they are a wg-quick-only directive and
      are not accepted by the lower-level ``wg setconf`` parser used inside
      the namespace.
    """
    lines: list[str] = []
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        stripped = key.strip().lower()
        if not separator:
            lines.append(line)
            continue
        if stripped == "dns":
            continue
        if stripped == "address":
            continue
        if stripped == "endpoint":
            port = value.strip().rstrip("]").rsplit(":", 1)[-1]
            lines.append(f"Endpoint = {endpoint_ip}:{port}")
            continue
        if stripped == "table":
            continue
        lines.append(line)
    return "\n".join(lines) + "\n"


class NamespaceManager:
    """Creates and supervises one WireGuard network namespace per location."""

    def __init__(self, specs: dict[str, VPNSpec]):
        self.specs = specs

    async def run(self, *args: str, check: bool = True) -> tuple[int, bytes, bytes]:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode is not None
        if check and process.returncode != 0:
            raise RuntimeError(
                f"{' '.join(args)} failed: {stderr.decode(errors='replace').strip()}"
            )
        return process.returncode, stdout, stderr

    async def ns_exec(self, spec: VPNSpec, *args: str, check: bool = True):
        return await self.run("ip", "netns", "exec", spec.namespace, *args, check=check)

    async def namespace_exists(self, spec: VPNSpec) -> bool:
        return await asyncio.to_thread(lambda: Path(f"/run/netns/{spec.namespace}").exists())

    async def tunnel_up(self, spec: VPNSpec) -> bool:
        if not await self.namespace_exists(spec):
            return False
        returncode, _, _ = await self.ns_exec(
            spec, "ip", "link", "show", spec.interface, check=False
        )
        return returncode == 0

    async def create_namespace(self, spec: VPNSpec) -> None:
        if not await self.namespace_exists(spec):
            # ip netns add bind-mounts into /run/netns; a shared mount avoids
            # failures on container root filesystems.
            await self.run("mount", "--make-shared", "/run/netns", check=False)
            await self.run("ip", "netns", "add", spec.namespace)
        await self.ns_exec(spec, "ip", "link", "set", "lo", "up")

    async def create_veth(self, spec: VPNSpec) -> None:
        # Clean up leftovers from a previous failed setup before checking.
        await self.run("ip", "link", "del", spec.veth_ns, check=False)
        returncode, _, _ = await self.run("ip", "link", "show", spec.veth_host, check=False)
        if returncode == 0:
            return
        await self.run(
            "ip",
            "link",
            "add",
            spec.veth_host,
            "type",
            "veth",
            "peer",
            "name",
            spec.veth_ns,
        )
        await self.run("ip", "link", "set", spec.veth_ns, "netns", spec.namespace)
        await self.run("ip", "addr", "add", spec.host_ip, "dev", spec.veth_host)
        await self.run("ip", "link", "set", spec.veth_host, "up")
        # eth0 is free inside the fresh namespace, so rename there.
        await self.ns_exec(spec, "ip", "link", "set", spec.veth_ns, "name", "eth0")
        await self.ns_exec(spec, "ip", "addr", "add", spec.ns_ip, "dev", "eth0")
        await self.ns_exec(spec, "ip", "link", "set", "eth0", "up")

    async def configure_routing(self, spec: VPNSpec) -> None:
        # The veth default route exists only long enough for the WireGuard
        # handshake to reach the host network. Scans run *inside* the
        # namespace, so scan traffic is locally originated (OUTPUT path) and
        # nothing is ever forwarded; ip_forward/rp_filter sysctls are neither
        # needed nor writable in a container (Docker mounts /proc/sys read-only).
        await self.ns_exec(
            spec, "ip", "route", "replace", "default", "via", spec.gateway, "dev", "eth0"
        )

    async def _ensure_rule(self, *rule: str, table: str | None = None) -> None:
        """Append an iptables rule in the caller's namespace if not present.

        ``rule`` excludes the subcommand and table flag. The table flag must
        come before the subcommand (``iptables -t <table> <sub> <chain> ...``).
        """
        table_args = ["-t", table] if table else []
        returncode, _, _ = await self.run(
            "iptables", *table_args, "-C", *rule, check=False
        )
        if returncode != 0:
            await self.run("iptables", *table_args, "-A", *rule)

    async def setup_host_nat(self, spec: VPNSpec) -> None:
        """NAT and forwarding on the caller's (persistent) namespace.

        The namespace's only link to the outside is the veth pair. Handshake
        packets from ``<subnet>.2`` must be masqueraded to the caller's own
        address so endpoint replies can find their way back, and forwarding
        from the veth to the caller's upstream must be permitted. These rules
        run in the caller's namespace, which must be the long-lived container
        (not the ephemeral init container) so the veth host end survives.
        """
        subnet = f"{spec.subnet}.0/24"
        # Masquerade traffic from the namespace subnet to the outside world.
        await self._ensure_rule(
            "POSTROUTING", "-s", subnet, "-j", "MASQUERADE", table="nat"
        )
        # Forward from the veth (namespace) to the caller's default interface.
        await self._ensure_rule("FORWARD", "-i", spec.veth_host, "-j", "ACCEPT")
        # Forward established replies back to the namespace.
        await self._ensure_rule(
            "FORWARD",
            "-o",
            spec.veth_host,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )

    async def setup_firewall(
        self, spec: VPNSpec, endpoint_ip: str, wg_port: int = 51820
    ) -> None:
        interface = spec.interface
        await self.ns_exec(spec, "iptables", "-F")
        await self.ns_exec(spec, "iptables", "-t", "nat", "-F")
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            await self.ns_exec(spec, "iptables", "-P", chain, "DROP")

        # Loopback.
        await self.ns_exec(spec, "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
        await self.ns_exec(spec, "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")

        # Established connections.
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            await self.ns_exec(
                spec,
                "iptables",
                "-A",
                chain,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            )

        # Host side -> VPN.
        await self.ns_exec(
            spec, "iptables", "-A", "FORWARD", "-i", "eth0", "-o", interface, "-j", "ACCEPT"
        )

        # VPN -> host side, replies only.
        await self.ns_exec(
            spec,
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            interface,
            "-o",
            "eth0",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )

        # NAT only through WireGuard.
        await self.ns_exec(
            spec,
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            interface,
            "-j",
            "MASQUERADE",
        )

        # Kill switch: never forward or emit traffic outside the tunnel.
        await self.ns_exec(
            spec, "iptables", "-A", "FORWARD", "-i", "eth0", "!", "-o", interface, "-j", "DROP"
        )
        # The encrypted WireGuard handshake to the resolved endpoint is the
        # only traffic allowed to leave the namespace unencrypted.
        await self.ns_exec(
            spec,
            "iptables",
            "-A",
            "OUTPUT",
            "-o",
            "eth0",
            "-p",
            "udp",
            "-d",
            endpoint_ip,
            "--dport",
            str(wg_port),
            "-j",
            "ACCEPT",
        )
        await self.ns_exec(spec, "iptables", "-A", "OUTPUT", "-o", interface, "-j", "ACCEPT")

    async def start(self, spec: VPNSpec) -> None:
        await self.create_namespace(spec)
        await self.create_veth(spec)
        await self.configure_routing(spec)
        await self.setup_host_nat(spec)

        config = Path(spec.config_path)
        if not await asyncio.to_thread(config.exists):
            raise RuntimeError(f"missing WireGuard config: {spec.config_path}")
        text = await asyncio.to_thread(config.read_text)
        wg_port = endpoint_port(text)
        address = interface_address(text)
        # Resolve the endpoint now, in the caller's namespace: the target
        # namespace has no DNS, and its resolver would route via the tunnel.
        endpoint_ip = await asyncio.to_thread(_resolve, endpoint_host(text))
        logger.info("location %s endpoint resolves to %s", spec.name, endpoint_ip)

        # Kill switch goes up before the tunnel.
        await self.setup_firewall(spec, endpoint_ip, wg_port)

        if not await self.tunnel_up(spec):
            # Raw wg + ip commands instead of wg-quick: wg-quick's policy
            # routing needs the src_valid_mark sysctl, which is not writable
            # in a container, and its DNS handling needs resolvconf.
            directory = await asyncio.to_thread(tempfile.mkdtemp, prefix="nmapaas-wg-")
            try:
                sanitized = Path(directory) / config.name
                await asyncio.to_thread(
                    sanitized.write_text, prepare_config(text, endpoint_ip)
                )
                await self.ns_exec(
                    spec, "ip", "link", "add", "dev", spec.interface, "type", "wireguard"
                )
                await self.ns_exec(spec, "wg", "setconf", spec.interface, str(sanitized))
                await self.ns_exec(
                    spec, "ip", "address", "add", "dev", spec.interface, address
                )
                await self.ns_exec(spec, "ip", "link", "set", "up", "dev", spec.interface)
            finally:
                shutil.rmtree(directory, ignore_errors=True)

        # Route all traffic via the tunnel, except the handshake to the
        # resolved endpoint, which keeps using the veth pair.
        await self.ns_exec(
            spec,
            "ip",
            "route",
            "replace",
            endpoint_ip,
            "via",
            spec.gateway,
            "dev",
            "eth0",
        )
        await self.ns_exec(
            spec, "ip", "route", "replace", "default", "dev", spec.interface
        )

    async def teardown(self, spec: VPNSpec) -> None:
        """Delete the veth pair and the namespace; the tunnel dies with them.

        Does not need the WireGuard config, so callers do not have to mount
        the VPN secrets (for example a preStop hook in the app container).
        """
        await self.run("ip", "link", "del", spec.veth_host, check=False)
        await self.run("ip", "link", "del", spec.veth_ns, check=False)
        if await self.namespace_exists(spec):
            await self.run("ip", "netns", "del", spec.namespace, check=False)

    async def public_ip(self, spec: VPNSpec) -> str | None:
        # Namespaces have no DNS resolver (scans only use literal IPs), so
        # this must hit a literal-IP endpoint. Cloudflare's trace returns
        # ``ip=<address>`` among its fields.
        _, stdout, _ = await self.run(
            "ip",
            "netns",
            "exec",
            spec.namespace,
            "curl",
            "-4",
            "--connect-timeout",
            "5",
            "https://1.1.1.1/cdn-cgi/trace",
            check=False,
        )
        for line in stdout.decode(errors="replace").splitlines():
            if line.startswith("ip="):
                return line.partition("=")[2].strip() or None
        return None

    async def verify(self, spec: VPNSpec, attempts: int = 10, delay: float = 3.0) -> str:
        """Confirm the tunnel passes traffic by fetching the exit public IP.

        The WireGuard handshake completes asynchronously after the interface
        comes up, so retry while it settles. Returns the tunnel's exit IP on
        success; raises if every attempt fails (e.g. a dead or leaking
        tunnel), so startup surfaces the failure instead of serving scans
        that silently bypass or drop.
        """
        last_error: str | None = None
        for attempt in range(1, attempts + 1):
            if not await self.tunnel_up(spec):
                last_error = "tunnel interface is down"
            else:
                ip = await self.public_ip(spec)
                if ip:
                    logger.info(
                        "location %s self-check passed: exit IP %s", spec.name, ip
                    )
                    return ip
                last_error = "no response from public-IP probe"
            logger.warning(
                "location %s self-check attempt %d/%d failed: %s",
                spec.name,
                attempt,
                attempts,
                last_error,
            )
            if attempt < attempts:
                await asyncio.sleep(delay)
        raise RuntimeError(
            f"self-check failed for location {spec.name}: {last_error}"
        )


async def _apply(action: str, specs: dict[str, VPNSpec]) -> int:
    """Run setup or teardown for every location; return the failure count."""
    manager = NamespaceManager(specs)
    failures = 0
    for spec in specs.values():
        try:
            if action == "setup":
                # Remove leftovers from a previous run so setup stays
                # idempotent after a failure or a dirty host.
                await manager.teardown(spec)
                await manager.start(spec)
                # Self-check: prove the tunnel carries traffic before
                # declaring the location ready.
                await manager.verify(spec)
            else:
                await manager.teardown(spec)
        except Exception as exc:
            logger.error("failed to %s location %s: %s", action, spec.name, exc)
            failures += 1
        else:
            logger.info("%s complete for location %s (%s)", action, spec.name, spec.namespace)
    return failures


def main(argv: list[str] | None = None) -> int:
    """One-shot network setup/teardown entry point, used by the init container."""
    from nmapaas.config import get_settings

    parser = argparse.ArgumentParser(prog="nmapaas-netns")
    parser.add_argument("action", choices=["setup", "teardown"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    specs = get_settings().vpn_specs
    if not specs:
        logger.info("no VPN-backed locations configured; nothing to %s", args.action)
        return 0
    failures = asyncio.run(_apply(args.action, specs))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
