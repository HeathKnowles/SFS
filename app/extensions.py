from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

Base = declarative_base()
db_session = None

def init_db_session(engine):
    """Configure and return a scoped DB session bound to engine."""
    global db_session
    db_session = scoped_session(sessionmaker(bind=engine))
    return db_session
