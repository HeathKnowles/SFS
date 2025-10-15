from flask import Blueprint, request, jsonify, current_app, session
from argon2 import PasswordHasher
from ..models import User
from ..extensions import db_session
from sqlalchemy.exc import IntegrityError
import re

from ..rate_limiter import allow_request
from ..email_utils import get_serializer, send_email
from itsdangerous import BadSignature, SignatureExpired
from flask_wtf.csrf import generate_csrf

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()
_serializer = None


def get_serializer_instance():
    global _serializer
    if _serializer is None:
        _serializer = get_serializer()
    return _serializer


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


@auth_bp.before_app_request
def _ensure_rate_limit():
    # apply a lightweight rate limit for auth endpoints
    if request.path.startswith('/api/') and request.endpoint and 'auth' in request.endpoint:
        ip = request.remote_addr or 'unknown'
        allowed = allow_request(ip, request.path, max_calls=10, period=60)
        if not allowed:
            return jsonify({'error': 'rate limit exceeded'}), 429


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'email and password required'}), 400
    if not validate_email(email):
        return jsonify({'error': 'invalid email'}), 400
    if len(password) < 8:
        return jsonify({'error': 'password too short (min 8)'}), 400

    # hash password
    pw_hash = ph.hash(password)

    user = User(email=email, password_hash=pw_hash)
    sess = db_session()
    try:
        sess.add(user)
        sess.commit()
    except IntegrityError:
        sess.rollback()
        return jsonify({'error': 'user already exists'}), 409

    # send verification email
    serializer = get_serializer_instance()
    token = serializer.dumps({'user_id': user.id, 'email': user.email})
    verify_url = f"{request.url_root.rstrip('/')}/api/verify-email?token={token}"
    send_email(user.email, 'Verify your email', f'Click to verify: {verify_url}')

    # create session
    session.clear()
    session['user_id'] = user.id
    return jsonify({'id': user.id, 'email': user.email}), 201


@auth_bp.route('/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'token required'}), 400
    serializer = get_serializer_instance()
    try:
        data = serializer.loads(token, max_age=60 * 60 * 24)
    except SignatureExpired:
        return jsonify({'error': 'token expired'}), 400
    except BadSignature:
        return jsonify({'error': 'invalid token'}), 400

    user_id = data.get('user_id')
    sess = db_session()
    user = sess.get(User, user_id)
    if not user:
        return jsonify({'error': 'user not found'}), 404
    # mark email as verified via a column — add if desired; for now we just acknowledge
    return jsonify({'status': 'email verified'}), 200


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'email and password required'}), 400

    sess = db_session()
    user = sess.query(User).filter_by(email=email).one_or_none()
    if not user:
        return jsonify({'error': 'invalid credentials'}), 401

    try:
        ph.verify(user.password_hash, password)
    except Exception:
        return jsonify({'error': 'invalid credentials'}), 401

    session.clear()
    session['user_id'] = user.id
    return jsonify({'id': user.id, 'email': user.email}), 200


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'ok'}), 200


@auth_bp.route('/password-reset/request', methods=['POST'])
def password_reset_request():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'email required'}), 400

    sess = db_session()
    user = sess.query(User).filter_by(email=email).one_or_none()
    if not user:
        # do not reveal whether user exists
        return jsonify({'status': 'ok'}), 200

    serializer = get_serializer_instance()
    token = serializer.dumps({'user_id': user.id})
    reset_url = f"{request.url_root.rstrip('/')}/api/password-reset/confirm?token={token}"
    send_email(user.email, 'Password reset', f'Reset: {reset_url}')
    return jsonify({'status': 'ok'}), 200


@auth_bp.route('/password-reset/confirm', methods=['POST', 'GET'])
def password_reset_confirm():
    if request.method == 'GET':
        # simple check link
        token = request.args.get('token')
        if not token:
            return jsonify({'error': 'token required'}), 400
        serializer = get_serializer_instance()
        try:
            data = serializer.loads(token, max_age=60 * 60)
        except SignatureExpired:
            return jsonify({'error': 'token expired'}), 400
        except BadSignature:
            return jsonify({'error': 'invalid token'}), 400
        return jsonify({'status': 'ok', 'token': token}), 200

    # POST: perform reset
    data = request.get_json() or {}
    token = data.get('token')
    new_password = data.get('password')
    if not token or not new_password:
        return jsonify({'error': 'token and password required'}), 400
    serializer = get_serializer_instance()
    try:
        payload = serializer.loads(token, max_age=60 * 60)
    except SignatureExpired:
        return jsonify({'error': 'token expired'}), 400
    except BadSignature:
        return jsonify({'error': 'invalid token'}), 400

    user_id = payload.get('user_id')
    sess = db_session()
    user = sess.get(User, user_id)
    if not user:
        return jsonify({'error': 'user not found'}), 404

    user.password_hash = ph.hash(new_password)
    sess.add(user)
    sess.commit()
    return jsonify({'status': 'password updated'}), 200


@auth_bp.route('/csrf-token', methods=['GET'])
def csrf_token():
    # Return a fresh CSRF token for API clients/tests
    token = generate_csrf()
    return jsonify({'csrf_token': token}), 200
