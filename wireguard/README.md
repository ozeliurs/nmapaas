# WireGuard configs

Place one WireGuard config per scan location in this directory, named
`<location>.conf` (for example `de-ber.conf`). The init container mounts
this directory read-only at `/etc/vpn` and brings each config up inside its
own network namespace with `wg-quick`. The tunnel interface takes the config
file's basename, so keep names short (15 characters or fewer). `DNS =`
directives are stripped automatically: scans only use literal IPs and the
image does not ship resolvconf.

Most VPN providers (including PIA and Mullvad) can generate plain WireGuard
config files. Configs contain private keys: they are excluded from Git and
from the Docker build context.
