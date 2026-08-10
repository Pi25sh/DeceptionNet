import os
import pytest

# Tests must be able to `import main` (and thus `database`) without a live
# Postgres. RUN_INIT_DB=0 skips the create_all retry loop at import time, and
# DATABASE_URL is pointed at SQLite so the module-level engine in database.py
# doesn't try to import the psycopg2 driver. Each test that needs a DB builds
# its own in-memory SQLite engine instead.
os.environ["RUN_INIT_DB"] = "0"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"


@pytest.fixture
def db_session():
    """Fresh in-memory SQLite DB + session for tests that exercise ORM code."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from database import Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
