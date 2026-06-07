import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from env_loader import load_project_env


load_project_env()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
