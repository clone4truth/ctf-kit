"""REST surface regression tests for registry/category parity."""

from fastapi.testclient import TestClient

import ctfkit.modules  # noqa: F401
from ctfkit.registry import CATEGORIES, TOOLS
from server import app


client = TestClient(app)


def test_health_and_tool_listing_match_registry():
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["tools_registered"] == len(TOOLS)
    assert health.json()["categories"] == sorted(CATEGORIES)

    listing = client.get("/api/tools")
    assert listing.status_code == 200
    assert listing.json()["total"] == len(TOOLS)
    assert {item["name"] for item in listing.json()["tools"]} == set(TOOLS)


def test_every_category_route_has_exact_registry_membership():
    for category in CATEGORIES:
        response = client.get(f"/api/categories/{category}")
        assert response.status_code == 200, category
        body = response.json()
        expected = {name for name, meta in TOOLS.items() if meta["category"] == category}
        assert body["total"] == len(expected)
        assert {item["name"] for item in body["tools"]} == expected


def test_category_execution_enforces_membership_and_uses_canonical_executor():
    success = client.post("/api/crypto/caesar", json={"text": "ABC", "shift": 1})
    assert success.status_code == 200
    assert success.json()["status"] == "success"
    assert "BCD" in success.json()["result"]

    mismatch = client.post("/api/web/caesar", json={"text": "ABC", "shift": 1})
    assert mismatch.status_code == 400

    invalid = client.post("/api/crypto/caesar", json={"unknown": "value"})
    assert invalid.status_code == 200
    assert invalid.json()["status"] == "invalid_input"
