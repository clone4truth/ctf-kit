"""REST surface regression tests for registry/category parity."""

import time

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
    assert health.json()["checks"]["job_manager"] is True

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
    assert success.json()["execution_id"]
    assert success.json()["source"] == "rest-category"
    assert "BCD" in success.json()["result"]

    mismatch = client.post("/api/web/caesar", json={"text": "ABC", "shift": 1})
    assert mismatch.status_code == 400

    invalid = client.post("/api/crypto/caesar", json={"unknown": "value"})
    assert invalid.status_code == 200
    assert invalid.json()["status"] == "invalid_input"


def test_central_telemetry_tracks_rest_source_and_recent_execution():
    result = client.post(
        "/api/run", json={"name": "caesar", "arguments": {"text": "XYZ", "shift": 1}},
        headers={"X-CTFKit-Source": "integration-test"},
    ).json()
    telemetry = client.get("/api/telemetry").json()
    assert telemetry["total_executions"] >= 1
    assert telemetry["status_counts"]["success"] >= 1
    event = next(item for item in telemetry["recent"] if item["id"] == result["execution_id"])
    assert event["source"] == "integration-test"
    assert event["tool"] == "caesar"

    active = client.get("/api/processes/list").json()
    assert active["ok"] and "executions" in active and "jobs" in active
    status = client.get(f"/api/executions/{result['execution_id']}").json()
    assert status["state"] == "finished"


def test_background_job_rest_lifecycle_and_incremental_output():
    submitted = client.post(
        "/api/jobs", json={"name": "caesar", "arguments": {"text": "ABC", "shift": 1}},
        headers={"X-CTFKit-Source": "rest-job-test"},
    )
    assert submitted.status_code == 202
    job_id = submitted.json()["job"]["id"]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()["job"]
        if job["status"] in {"completed", "failed", "cancelled", "interrupted"}:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("REST background job did not finish")

    assert job["status"] == "completed"
    assert job["result"]["status"] == "success"
    assert "BCD" in job["result"]["text"]
    output = client.get(f"/api/jobs/{job_id}/output", params={"offset": 0}).json()
    assert output["terminal"] is True
    assert output["next_offset"] >= 0
    assert any(item["id"] == job_id for item in client.get("/api/jobs").json()["jobs"])
    assert client.get("/api/telemetry").json()["jobs"]["total"] >= 1
    with client.stream("GET", f"/api/jobs/{job_id}/stream") as stream:
        events = "".join(stream.iter_text())
    assert "event: status" in events
    assert '"status": "completed"' in events


def test_background_job_rejects_unknown_tools_and_unknown_arguments():
    missing = client.post("/api/jobs", json={"name": "does_not_exist", "arguments": {}})
    assert missing.status_code == 400
    invalid = client.post("/api/jobs", json={"name": "caesar", "arguments": {"wrong": 1}})
    assert invalid.status_code == 400
