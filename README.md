# nmapaas

A location-aware Nmap HTTP API. FastAPI accepts authenticated scan requests, Redis stores jobs and progress, and worker pods run Nmap through Private Internet Access VPN exits.

Only scan systems you own or have explicit permission to test.

## API

Create a scan:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H 'Authorization: Bearer development-key' \
  -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.8","location":"local","profile":"quick"}'
```

Poll progress and results:

```bash
curl -H 'Authorization: Bearer development-key' \
  http://localhost:8000/v1/scans/SCAN_ID
```

Cancel a queued or running scan:

```bash
curl -X DELETE -H 'Authorization: Bearer development-key' \
  http://localhost:8000/v1/scans/SCAN_ID
```

Profiles are fixed to `quick`, `standard`, and `full`; the API never accepts arbitrary Nmap arguments. Targets must be literal IPv4 or IPv6 addresses. Private, loopback, link-local, multicast, reserved, and unspecified targets are denied unless `ALLOW_PRIVATE_TARGETS=true`. `ALLOWED_TARGET_CIDRS` can further restrict targets.

## Local Development

Docker Compose runs Redis, the API, and one worker without a VPN:

```bash
API_KEY=development-key docker compose up --build
```

OpenAPI is available at `http://localhost:8000/docs`.

For Python development:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check .
pytest
```

## Kubernetes And PIA

The Helm chart creates API replicas, persistent Redis, and one deployment per entry in `locations`. Every worker pod contains:

- A `gluetun` sidecar connected to the configured PIA region.
- An unprivileged worker sharing the pod network namespace, so Nmap traffic exits through that VPN.
- `WORKER_CONCURRENCY` independent consumers. Total location concurrency is `replicas * concurrency`.

Workers wait for Gluetun's health endpoint before consuming jobs. Gluetun uses PIA's supported OpenVPN integration and maintains a firewall kill switch if the tunnel drops.

Create secrets outside Helm so credentials do not enter values or release history:

```bash
kubectl create namespace nmapaas
kubectl -n nmapaas create secret generic nmapaas-api --from-literal=api-key='replace-me'
kubectl -n nmapaas create secret generic nmapaas-pia \
  --from-literal=username='PIA_USERNAME' \
  --from-literal=password='PIA_PASSWORD'
```

Create a production values file with your GHCR image and locations:

```yaml
image:
  repository: ghcr.io/your-org/nmapaas
  tag: main
auth:
  existingSecret: nmapaas-api
pia:
  existingSecret: nmapaas-pia
  clusterOutboundSubnets: "10.0.0.0/8"
locations:
  - name: us-east
    piaRegion: US East
    replicas: 2
    concurrency: 3
  - name: sweden
    piaRegion: Sweden
    replicas: 1
    concurrency: 2
```

`pia.clusterOutboundSubnets` must include the cluster service and pod CIDRs so the VPN firewall permits Redis access. The Kubernetes nodes must expose `/dev/net/tun`, and their admission policy must allow `NET_ADMIN` on the VPN sidecar.

Install:

```bash
helm upgrade --install nmapaas charts/nmapaas \
  --namespace nmapaas \
  --values production-values.yaml
```

Expose `nmapaas-nmapaas-api` using your ingress controller or change `api.service.type`. Keep authentication enabled and add network-level access controls before exposing it publicly.

## Delivery

`.github/workflows/ci.yaml` runs Ruff, tests, and Helm lint on pull requests. Pushes to `main` and `v*` tags build the image and publish branch, tag, and commit-SHA tags to `ghcr.io/<owner>/<repository>` using `GITHUB_TOKEN`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | `redis://localhost:6379/0` | Shared job store |
| `API_KEY` | empty | Bearer token; set this in every deployment |
| `SCAN_LOCATIONS` | `local` | Comma-separated locations accepted by the API |
| `SCAN_LOCATION` | `local` | Queue consumed by a worker |
| `WORKER_CONCURRENCY` | `2` | Concurrent scans in each worker pod |
| `JOB_TTL_SECONDS` | `86400` | Job and result retention |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Per-scan hard timeout |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit non-public IPs |
| `ALLOWED_TARGET_CIDRS` | empty | Optional comma-separated allowlist |
| `VPN_HEALTH_URL` | empty | Optional VPN health gate used by Kubernetes workers |
