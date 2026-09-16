```python
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# Use PostgreSQL when DATABASE_URL is provided by Render.
# Otherwise, use the existing local SQLite database.
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Render may provide a URL beginning with postgres://.
    # SQLAlchemy uses postgresql://.
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace(
            "postgres://",
            "postgresql://",
            1
        )

    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True
    )

else:
    # Local AEGIS database
    DATABASE_URL = "sqlite:///./aegis.db"

    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
```
