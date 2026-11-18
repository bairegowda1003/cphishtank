from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate_auth_schema() -> None:
    """Add auth columns to databases created before email verification existed."""
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "email_verified" not in columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT TRUE"
            ))
        if "token_version" not in columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"
            ))
