# nmapaas

A queued Nmap HTTP API with concurrent, location-aware workers. Each Kubernetes worker pod runs Nmap beside a PIA WireGuard sidecar, so scans use a real VPN network interface and preserve accurate TCP connection results.

Only scan systems you own or have explicit permission to test.

## Architecture

- One FastAPI replica accepts authenticated jobs and reports progress.
- One small persistent Redis instance stores queues, jobs, progress, and results.
- One worker Deployment is rendered for each configured PIA location.
- Every worker pod has an unprivileged Nmap container and a `thrnz/docker-wireguard-pia` sidecar sharing the pod network namespace.
- The sidecar enables its firewall kill switch before creating the tunnel. The worker waits for a shared readiness marker before consuming jobs.
- `replicas * concurrency` controls simultaneous scans in each region.

Workers use unprivileged TCP connect scans (`-sT`) with host discovery disabled (`-Pn`). Fixed profiles prevent arbitrary Nmap argument injection.

## API

Create a scan:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H 'Authorization: Bearer development-key' \
  -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.8","location":"swiss","profile":"quick"}'
```

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

Docker Compose runs Redis, the API, and one worker behind a PIA WireGuard sidecar. OrbStack must be running and provide `/dev/net/tun`. Configure `.env` using the variables shown in `.env.example`; `.env` is excluded from both Git and Docker build contexts.

```bash
docker compose up --build
```

The stack waits for a healthy WireGuard tunnel before starting the worker. OpenAPI is available at `http://localhost:8000/docs`. Change `PIA_LOCATION` and recreate the stack to use another PIA region.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check .
pytest
```

## Kubernetes

The Helm chart uses PIA location IDs from `https://serverlist.piaservers.net/vpninfo/servers/v7`. API names may be friendly aliases, while `piaLocation` must be the exact PIA ID.

Create credentials outside Helm values:

```bash
kubectl create namespace nmapaas
kubectl -n nmapaas create secret generic nmapaas-api \
  --from-literal=api-key='replace-me'
kubectl -n nmapaas create secret generic nmapaas-pia \
  --from-literal=username='PIA_USERNAME' \
  --from-literal=password='PIA_PASSWORD'
```

Create `production-values.yaml`:

```yaml
image:
  repository: ghcr.io/your-org/nmapaas
  tag: main
auth:
  existingSecret: nmapaas-api
pia:
  existingSecret: nmapaas-pia
  # Include both your Kubernetes service CIDR and pod CIDR.
  localNetworks: "10.0.0.0/8"
locations:
  - name: swiss
    piaLocation: swiss
    replicas: 1
    concurrency: 2
  - name: us-california
    piaLocation: us_california
    replicas: 1
    concurrency: 2
```

Install:

```bash
helm upgrade --install nmapaas charts/nmapaas \
  --namespace nmapaas \
  --values production-values.yaml
```

The cluster nodes must provide `/dev/net/tun`, support WireGuard, and allow `NET_ADMIN` for the VPN sidecar. Pod admission must permit the `net.ipv4.conf.all.src_valid_mark=1` sysctl. Set `pia.localNetworks` correctly or the VPN firewall may block worker access to Redis. No port forwarding is enabled.

The API service is `nmapaas-nmapaas-api`. Expose it through your ingress controller and add network-level access controls before making it public.

## Delivery

`.github/workflows/ci.yaml` runs Ruff, tests, and Helm lint. Pushes to `main` and `v*` tags publish branch, tag, and commit-SHA image tags to `ghcr.io/<owner>/<repository>`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | `redis://localhost:6379/0` | Shared job store |
| `API_KEY` | empty | Bearer token; always set in deployment |
| `SCAN_LOCATIONS` | `local` | Comma-separated locations accepted by the API |
| `SCAN_LOCATION` | `local` | Queue consumed by a worker |
| `WORKER_CONCURRENCY` | `2` | Concurrent scans per worker pod |
| `JOB_TTL_SECONDS` | `86400` | Job and result retention in Redis |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Per-scan hard timeout |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit non-public targets |
| `ALLOWED_TARGET_CIDRS` | empty | Optional comma-separated target allowlist |
| `VPN_READY_FILE` | empty | Tunnel readiness marker used by VPN workers |
