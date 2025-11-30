"""
tests/test_basic.py

Basic functionality tests and database tests.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from worker.db import Base, Job, Run, AuditData, Vulnerability


def test_sample():
    """Basic arithmetic test."""
    assert 1 + 1 == 2


def test_database_models():
    """Test that database models can be instantiated."""
    # Test Job model
    job = Job(
        type="wifi_recon",
        profile="stealth_recon",
        params={"interface": "wlan0"},
        status="queued"
    )
    assert job.type == "wifi_recon"
    assert job.status == "queued"

    # Test Run model
    run = Run(
        job_id=1,
        stdout="Test output",
        stderr="",
        exit_code=0
    )
    assert run.job_id == 1
    assert run.exit_code == 0

    # Test AuditData model
    audit_data = AuditData(
        job_id=1,
        data_type="wifi_network",
        data={"ssid": "TestNetwork"}
    )
    assert audit_data.data_type == "wifi_network"

    # Test Vulnerability model
    vuln = Vulnerability(
        job_id=1,
        vuln_type="wifi",
        severity="high",
        description="Test vulnerability"
    )
    assert vuln.severity == "high"


@pytest.fixture
def test_db():
    """Create a test database."""
    engine = create_engine("sqlite:///:memory:")
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create tables
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_database_operations(test_db):
    """Test basic database operations."""
    # Create a job
    job = Job(
        type="wifi_recon",
        profile="stealth_recon",
        params={"interface": "wlan0"},
        status="queued"
    )
    test_db.add(job)
    test_db.commit()
    test_db.refresh(job)

    # Verify job was created
    assert job.id is not None
    assert job.status == "queued"

    # Query the job back
    queried_job = test_db.query(Job).filter(Job.id == job.id).first()
    assert queried_job is not None
    assert queried_job.type == "wifi_recon"

    # Update job status
    queried_job.status = "running"
    test_db.commit()

    # Verify update
    updated_job = test_db.query(Job).filter(Job.id == job.id).first()
    assert updated_job.status == "running"

