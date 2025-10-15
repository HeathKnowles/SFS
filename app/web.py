from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from .extensions import db_session
from .models import User
from .models import File as FileModel, FileShare
from argon2 import PasswordHasher
from sqlalchemy.exc import IntegrityError

web = Blueprint('web', __name__)
ph = PasswordHasher()


@web.route('/')
def index():
    user_id = session.get('user_id')
    if user_id:
        sess = db_session()
        from .models import File as FileModel
        files = sess.query(FileModel).filter_by(owner_id=user_id).order_by(FileModel.created_at.desc()).all()
        # fetch shares for these files
        file_ids = [f.id for f in files]
        shares = {}
        if file_ids:
            rows = sess.query(FileShare).filter(FileShare.file_id.in_(file_ids)).all()
            for s in rows:
                shares.setdefault(s.file_id, []).append(s)
    return render_template('dashboard.html', files=files, shares=shares)
    return redirect(url_for('web.login'))


@web.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    sess = db_session()
    user = sess.query(User).filter_by(email=email).one_or_none()
    if not user:
        flash('Invalid credentials')
        return render_template('login.html')
    try:
        ph.verify(user.password_hash, password)
    except Exception:
        flash('Invalid credentials')
        return render_template('login.html')

    session.clear()
    session['user_id'] = user.id
    return redirect(url_for('web.index'))


@web.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    if not email or not password:
        flash('Email and password required')
        return render_template('register.html')
    sess = db_session()
    try:
        user = User(email=email, password_hash=ph.hash(password))
        sess.add(user)
        sess.commit()
    except IntegrityError:
        sess.rollback()
        flash('User already exists')
        return render_template('register.html')

    session.clear()
    session['user_id'] = user.id
    return redirect(url_for('web.index'))


@web.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('web.login'))
