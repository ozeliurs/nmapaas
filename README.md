# nmapaas

A queued Nmap HTTP API with concurrent, location-aware scanning. One container serves the API and runs the scans; at startup it creates a Linux network namespace per location, brings a WireGuard tunnel up inside each, and runs Nmap through `ip netns exec` — no per-location containers or sidecars.

Only scan systems you own or have explicit permission to test.

## Architecture

A single `app` container does everything. Its entrypoint ([docker-entrypoint.sh](docker-entrypoint.sh)) runs `nmapaas-netns setup` before starting Uvicorn, so the network state lives in the same long-lived network namespace as the process that uses it. For each location, setup:

- creates a dedicated network namespace `vpn-<name>`,
- creates a veth pair: `<subnet>.1` on the app container, `<subnet>.2` (renamed `eth0`) inside the namespace,
- brings up a WireGuard tunnel whose interface is named after the config file's basename (e.g. `de-ber`),
- installs host-side NAT (`MASQUERADE` for the namespace subnet) plus forwarding rules in the app container, so the encrypted handshake can reach the VPN endpoint and replies can return,
- installs an iptables **kill switch** inside the namespace that drops any packet not going through the tunnel interface,
- runs a **startup self-check**: it curls a literal-IP echo endpoint through the tunnel and confirms the exit IP before marking the location ready. If the tunnel never carries traffic, setup fails and the container exits instead of serving scans that silently drop or leak.

Scans run **inside** the namespace (`ip netns exec vpn-<name> nmap ...`), so scan traffic is locally originated and always exits through the tunnel. The only plaintext traffic allowed out of a namespace is the encrypted WireGuard handshake to the resolved endpoint IP.

A few deliberate choices, driven by what containers can actually do:

- **Raw `wg` + `ip` commands, not `wg-quick`.** `wg-quick`'s policy routing needs the `net.ipv4.conf.all.src_valid_mark` sysctl and its DNS handling needs `resolvconf`, neither of which is available in a container (`/proc/sys` is read-only).
- **No per-namespace sysctls.** `ip_forward`/`rp_filter` aren't writable in a container, and aren't needed: scan traffic is originated, not forwarded. The host-side `ip_forward` (Docker sets it to `1` by default) is what carries the handshake.
- **No DNS in the namespaces.** The resolver would route through the tunnel, so lookups are impossible by design. Scans only use literal IPs (the API rejects hostnames), and the public-IP probe hits a literal-IP endpoint.
- **Endpoint hostnames are resolved before entering the namespace**, then injected into the config as a literal `Endpoint` IP, since the namespace has no DNS.
- **Setup is idempotent.** Each run tears down any leftovers from a previous run first, so a restart recreates everything cleanly.

If a tunnel drops while the app is running, scans for that location fail fast rather than leaving the VPN; restart the container to re-run setup.

Scans use unprivileged TCP connect scans (`-sT`) with host discovery disabled (`-Pn`). Fixed profiles prevent arbitrary Nmap argument injection.

## API

Create a scan:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H 'Authorization: Bearer development-key' \
  -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.8","profile":"quick"}'
```

The optional `location` defaults to `default`, which selects the configured location with the
fewest queued and running scans. Set a location explicitly to route a scan to that namespace.

List configured regions:

```bash
curl -H 'Authorization: Bearer development-key' \
  http://localhost:8000/v1/locations
```

Poll progress or cancel a scan:

```bash
curl -H 'Authorization: Bearer development-key' \
  http://localhost:8000/v1/scans/SCAN_ID

curl -X DELETE -H 'Authorization: Bearer development-key' \
  http://localhost:8000/v1/scans/SCAN_ID
```

Profiles are `quick`, `standard`, and `full`. Targets must be literal IPv4 or IPv6 addresses. Private, loopback, link-local, multicast, reserved, and unspecified targets are denied unless `ALLOW_PRIVATE_TARGETS=true`. `ALLOWED_TARGET_CIDRS` can further restrict targets.

## Local Development

Docker Compose runs Redis and the single merged `app` container (API + scan consumers + network setup). The host must provide `/dev/net/tun` and support WireGuard (kernel module or wireguard-go). Configure `.env` using the variables shown in `.env.example`; `.env` is excluded from both Git and Docker build contexts.

Drop one WireGuard config per location into `./wireguard/`, named `<location>.conf` (for example `de-ber.conf`). Providers such as PIA, Mullvad, and Surfshark can generate plain WireGuard configs. Keep config basenames short — the tunnel interface takes the basename and kernel interface names are limited to 15 characters. List locations with the `LOCATIONS` variable — each entry is `name` (scan directly) or `name:subnet-prefix` (WireGuard namespace):

```
LOCATIONS=de-ber:10.200.1,de-fra:10.200.2,jp-tok:10.200.3
```

A `name:subnet-prefix` entry like `de-ber` gets namespace `vpn-de-ber` with a veth pair on `10.200.1.0/24` and uses `/etc/vpn/de-ber.conf`; a plain `name` entry scans directly without a VPN. `DNS =` directives are stripped automatically (the namespace has no resolver), and the `Endpoint` hostname is resolved before entering the namespace.

```bash
docker compose up --build
```

On startup the app logs one self-check line per location before serving:

```
location de-ber self-check passed: exit IP 152.89.163.230
```

The app needs `NET_ADMIN` and `SYS_ADMIN` (granted in [compose.yaml](compose.yaml)) to manage namespaces and enter them with `ip netns exec`. OpenAPI is at `http://localhost:8000/docs`.

To remove the namespaces, veth pairs, and NAT rules without stopping the stack:

```bash
docker compose run --rm netns-teardown
```

### Tests and lint

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check .
pytest
```

## Kubernetes

The Helm chart runs the same single-container model as Compose: the pod's one container runs the image entrypoint, which sets up the namespaces and tunnels at startup (failing fast if the self-check fails) before serving HTTP. Create credentials outside Helm values. The VPN secret holds one WireGuard config per location, with keys named `<location>.conf`:

```bash
kubectl create namespace nmapaas
kubectl -n nmapaas create secret generic nmapaas-api \
  --from-literal=api-key='replace-me'
kubectl -n nmapaas create secret generic nmapaas-vpn \
  --from-file=de-ber.conf=./de-ber.conf \
  --from-file=jp-tok.conf=./jp-tok.conf
```

Create `production-values.yaml`:

```yaml
image:
  repository: ghcr.io/your-org/nmapaas
  tag: main
auth:
  existingSecret: nmapaas-api
vpn:
  existingSecret: nmapaas-vpn
app:
  replicas: 1
  concurrency: 2
locations:
  - name: de-ber
    subnet: "10.200.1"
  - name: jp-tok
    subnet: "10.200.3"
```

Install:

```bash
helm upgrade --install nmapaas charts/nmapaas \
  --namespace nmapaas \
  --values production-values.yaml
```

The cluster nodes must provide `/dev/net/tun` and support WireGuard (kernel module or wireguard-go). The pod runs a single non-privileged container with the `NET_ADMIN` and `SYS_ADMIN` capabilities; no init container, mount propagation, or privileged mode is required. Keep `app.replicas` at 1: network namespaces are per-node and would collide. Location subnets must not overlap each other or the pod network. No port forwarding is enabled.

The API service is `nmapaas-nmapaas`. Expose it through your ingress controller and add network-level access controls before making it public.

## Delivery

`.github/workflows/ci.yaml` runs Ruff, tests, and Helm lint. Pushes to `main` and `v*` tags publish branch, tag, and commit-SHA image tags to `ghcr.io/<owner>/<repository>`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | `redis://localhost:6379/0` | Shared job store |
| `API_KEY` | empty | Bearer token; always set in deployment |
| `LOCATIONS` | `local` | Comma-separated locations: `name` (direct) or `name:subnet-prefix` (WireGuard namespace) |
| `VPN_CONFIG_DIR` | `/etc/vpn` | Directory holding `<location>.conf` WireGuard configs |
| `WORKER_CONCURRENCY` | `2` | Concurrent scans per location queue |
| `JOB_TTL_SECONDS` | `86400` | Job and result retention in Redis |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Per-scan hard timeout |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit non-public targets |
| `ALLOWED_TARGET_CIDRS` | empty | Optional comma-separated target allowlist |
| `SKIP_NETNS_SETUP` | `0` | Set to `1` to skip namespace setup at container start (e.g. API-only run) |
