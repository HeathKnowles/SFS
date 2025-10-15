from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

Base = declarative_base()
db_session = None

def create_app(config_object=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///sfs.db'),
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret'),
    )

    # initialize DB engine and session
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], future=True)
    global db_session
    db_session = scoped_session(sessionmaker(bind=engine))

    # Attach session and engine to app for convenience
    app.db_engine = engine
    app.db_session = db_session

    # import models so Base.metadata.create_all works
    from . import models  # noqa: F401

    return app
