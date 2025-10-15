from flask import Flask
from sqlalchemy import create_engine
import os

from .extensions import init_db_session, Base
import os
try:
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import generate_csrf
except Exception as e:
    raise RuntimeError('Flask-WTF is required for strict CSRF mode. Please install Flask-WTF.') from e


def create_app(config_object=None):
    # enable static and templates directories inside the app package
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///sfs.db'),
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret'),
    )

    # initialize DB engine and session
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], future=True)
    db_session = init_db_session(engine)

    # Attach session and engine to app for convenience
    app.db_engine = engine
    app.db_session = db_session

    # CSRF protection (strict)
    csrf = CSRFProtect()
    csrf.init_app(app)

    # secure cookie settings
    app.config.update(
        SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true',
        SESSION_COOKIE_HTTPONLY=os.environ.get('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true',
        SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
    )

    @app.context_processor
    def inject_csrf_token():
        # Make the csrf token available in templates via `csrf_token()`
        return dict(csrf_token=(lambda: generate_csrf()))

    # import models so Base.metadata.create_all works
    try:
        # models will import Base from extensions
        from .models import models as models_pkg  # noqa: F401
    except Exception:
        pass

    # register blueprints (import after db_session is set)
    try:
        from .auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/api')
    except Exception:
        # defer registration errors until runtime
        pass
    try:
        from .files import files_bp
        app.register_blueprint(files_bp, url_prefix='/api')
    except Exception:
        pass
    try:
        from .web import web as web_bp
        app.register_blueprint(web_bp)
    except Exception:
        pass
    try:
        from .shares import shares as shares_bp
        app.register_blueprint(shares_bp)
    except Exception:
        pass

    return app
