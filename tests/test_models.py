from ipaddress import ip_address

import pytest
from fastapi import HTTPException

from nmapaas.api import validate_target
from nmapaas.config import Settings
from nmapaas.models import ScanCreate


def request_for(target: str) -> ScanCreate:
    return ScanCreate(target=ip_address(target), location="us-east", profile="quick")


def test_public_target_is_allowed() -> None:
    validate_target(request_for("8.8.8.8"), Settings())


def test_private_target_is_rejected_by_default() -> None:
    with pytest.raises(HTTPException, match="non-public targets"):
        validate_target(request_for("10.0.0.1"), Settings())


def test_target_must_match_configured_allowlist() -> None:
    settings = Settings(allowed_target_cidrs="1.1.1.0/24")
    with pytest.raises(HTTPException, match="outside allowed CIDRs"):
        validate_target(request_for("8.8.8.8"), settings)


def test_pia_location_names_allow_underscores() -> None:
    request = ScanCreate(target=ip_address("8.8.8.8"), location="us_south_west")
    assert request.location == "us_south_west"


def test_location_defaults_to_least_loaded_selector() -> None:
    request = ScanCreate(target=ip_address("8.8.8.8"))
    assert request.location == "default"
