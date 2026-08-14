from pathlib import Path

from nmapaas.scanner import PROGRESS_PATTERN, parse_nmap_xml


def test_progress_pattern() -> None:
    match = PROGRESS_PATTERN.search("Stats: 0:00:04 elapsed; About 37.50% done")
    assert match
    assert float(match.group(1)) == 37.5


def test_parse_nmap_xml(tmp_path: Path) -> None:
    result_path = tmp_path / "result.xml"
    result_path.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.27"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="2.42"/></runstats>
</nmaprun>
"""
    )

    result = parse_nmap_xml(result_path)

    assert result["elapsed_seconds"] == 2.42
    assert result["hosts"][0]["status"] == "up"
    assert result["hosts"][0]["ports"][0] == {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "product": "nginx",
        "version": "1.27",
    }
