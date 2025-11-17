"""
tests/test_api.py

Basic tests for the FastAPI application.
"""

def test_dummy():
    """A dummy test to check if pytest finds tests."""
    assert True


import pytest
from fastapi.testclient import TestClient

from api.main import app


"""
tests/test_api.py

Basic tests for the FastAPI application.
"""

def test_dummy():
    """A dummy test to check if pytest finds tests."""
    assert True


@pytest.fixture
def client():
    """Test client for FastAPI app."""
    from api.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_health_endpoint(client):
    """Test the /health endpoint returns 200."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"


def test_jobs_endpoint_get(client):
    """Test the /jobs GET endpoint."""
    response = client.get("/jobs")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)