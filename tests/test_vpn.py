import pytest

from nmapaas.config import Settings
from nmapaas.vpn import (
    VPNSpec,
    endpoint_host,
    endpoint_port,
    interface_address,
    main,
    prepare_config,
)


def test_vpn_spec_derives_namespace_and_addresses() -> None:
    spec = VPNSpec(name="fr", subnet="10.200.1", config_path="/etc/vpn/fr.conf")

    assert spec.namespace == "vpn-fr"
    assert spec.host_ip == "10.200.1.1/24"
    assert spec.ns_ip == "10.200.1.2/24"
    assert spec.gateway == "10.200.1.1"
    assert spec.veth_host == "veth-fr"


def test_veth_name_stays_within_interface_limit() -> None:
    spec = VPNSpec(name="a-very-long-location-name", subnet="10.200.9", config_path="x.conf")

    assert len(spec.veth_host) <= 15
    assert len(spec.veth_ns) <= 15
    # The peer must not be named eth0: both veth ends are created in the
    # caller's own namespace, which already has a Docker eth0.
    assert spec.veth_ns != "eth0"


def test_interface_name_comes_from_config_basename() -> None:
    spec = VPNSpec(name="jp-tok", subnet="10.200.3", config_path="/etc/vpn/jp-tok.conf")

    assert spec.interface == "jp-tok"


def test_strip_dns_removes_dns_lines_only() -> None:
    text = (
        "[Interface]\n"
        "PrivateKey = abc\n"
        "DNS = 162.252.172.57, 149.154.159.92\n"
        "[Peer]\n"
        "Endpoint = jp-tok.example.com:51820\n"
    )

    result = prepare_config(text, "203.0.113.10")

    assert "DNS" not in result
    assert "PrivateKey = abc" in result
    # The hostname is replaced with the resolved literal IP.
    assert "Endpoint = 203.0.113.10:51820" in result
    # wg setconf does not accept the Table directive; keep the veth default
    # route and avoid policy routing entirely.
    assert "Table" not in result


def test_endpoint_host_parsing() -> None:
    assert endpoint_host("Endpoint = de-ber.example.com:51820\n") == "de-ber.example.com"
    assert endpoint_host("Endpoint = [2001:db8::1]:51820\n") == "2001:db8::1"
    with pytest.raises(ValueError, match="no Endpoint"):
        endpoint_host("[Interface]\n")


def test_endpoint_port_parsing() -> None:
    assert endpoint_port("Endpoint = de-ber.example.com:51820\n") == 51820
    assert endpoint_port("Endpoint = [2001:db8::1]:51821\n") == 51821
    assert endpoint_port("[Interface]\n") == 51820


def test_interface_address_parsing() -> None:
    assert interface_address("Address = 10.14.0.2/16\n") == "10.14.0.2/16"
    assert interface_address("Address = 10.14.0.2/16, fc00:bbbb::2/128\n") == "10.14.0.2/16"
    with pytest.raises(ValueError, match="no Address"):
        interface_address("[Interface]\n")


def test_vpn_locations_parsing() -> None:
    settings = Settings(locations="fr:10.200.1, us:10.200.2", vpn_config_dir="/configs")

    specs = settings.vpn_specs

    assert set(specs) == {"fr", "us"}
    assert specs["fr"].subnet == "10.200.1"
    assert specs["us"].config_path == "/configs/us.conf"


def test_location_without_subnet_is_direct() -> None:
    settings = Settings(locations="fr:10.200.1, local", vpn_config_dir="/configs")

    assert settings.location_names == {"fr", "local"}
    assert settings.location_specs["local"] is None
    assert set(settings.vpn_specs) == {"fr"}


def test_empty_locations_default_to_local_direct() -> None:
    settings = Settings()

    assert settings.location_names == {"local"}
    assert settings.vpn_specs == {}


def test_invalid_location_entry_is_rejected() -> None:
    settings = Settings(locations="fr:")
    with pytest.raises(ValueError, match="invalid LOCATIONS entry"):
        _ = settings.vpn_specs


def test_duplicate_location_name_is_rejected() -> None:
    settings = Settings(locations="fr:10.200.1, fr")
    with pytest.raises(ValueError, match="duplicate LOCATIONS entry"):
        _ = settings.vpn_specs


def test_overlong_location_name_is_rejected() -> None:
    settings = Settings(locations="a-very-long-location-name:10.200.9")
    with pytest.raises(ValueError, match="15 characters"):
        _ = settings.vpn_specs


def test_netns_cli_without_locations_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCATIONS", raising=False)

    assert main(["setup"]) == 0
    assert main(["teardown"]) == 0
