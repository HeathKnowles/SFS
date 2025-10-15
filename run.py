import os
from app import create_app, Base


def init_db():
    app = create_app()
    engine = app.db_engine
    print(f"Creating tables on {engine}")
    Base.metadata.create_all(bind=engine)
    print("Tables created")


if __name__ == '__main__':
    init_db()
