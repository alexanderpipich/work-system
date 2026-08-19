import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from env_loader import load_project_env


load_project_env()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Сеть Timeweb рвёт праздные TCP-соединения пула: без pre_ping первый запрос
# после простоя получал мёртвое соединение и падал.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # проверять соединение перед выдачей из пула
    pool_recycle=300,     # принудительно обновлять соединения старше 5 минут
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
