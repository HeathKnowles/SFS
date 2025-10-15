from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.utils import secure_filename
from ..extensions import db_session
from ..models import File, FileShare
from ..models import AuditLog
import secrets
from datetime import datetime, timedelta
from ..storage import r2
import os
import tempfile
import hashlib
import uuid
import magic
import clamd
import shutil

files_bp = Blueprint('files', __name__)

MAX_UPLOAD_SIZE = int(os.environ.get('MAX_UPLOAD_SIZE', 50 * 1024 * 1024))  # 50MB default
UPLOAD_DIR = os.environ.get('UPLOAD_DIR', os.path.join(os.getcwd(), 'uploads'))
QUARANTINE_DIR = os.environ.get('QUARANTINE_DIR', os.path.join(os.getcwd(), 'quarantine'))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)


def connect_clamd():
    host = os.environ.get('CLAMAV_HOST')
    port = int(os.environ.get('CLAMAV_PORT', '3310')) if os.environ.get('CLAMAV_PORT') else None
    try:
        if host and port:
            cd = clamd.ClamdNetworkSocket(host=host, port=port)
        else:
            cd = clamd.ClamdUnixSocket()
        # ping to verify
        cd.ping()
        return cd
    except Exception:
        # raise so callers can handle
        raise


def scan_file_with_clamd(path: str):
    cd = connect_clamd()
    # clamd.scan returns dict {path: (status, signature)}
    res = cd.scan(path)
    if not res:
        return {'status': 'unknown', 'raw': res}
    entry = next(iter(res.values()))
    status = entry[0]
    signature = entry[1]
    return {'status': status, 'signature': signature, 'raw': res}


@files_bp.route('/upload', methods=['POST'])
def upload():
    # require authenticated user
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'authentication required'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'no file provided'}), 400

    f = request.files['file']
    filename = secure_filename(f.filename or '')
    if not filename:
        return jsonify({'error': 'invalid filename'}), 400

    # enforce content length if provided
    content_length = request.content_length
    if content_length and content_length > MAX_UPLOAD_SIZE:
        return jsonify({'error': 'file too large'}), 413

    # stream to temp file while enforcing size
    tmp = tempfile.NamedTemporaryFile(delete=False)
    total = 0
    try:
        chunk_size = 8192
        while True:
            chunk = f.stream.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_SIZE:
                tmp.close()
                os.unlink(tmp.name)
                return jsonify({'error': 'file too large'}), 413
            tmp.write(chunk)
        tmp.flush()
        tmp.close()

        # sniff mime type
        try:
            m = magic.Magic(mime=True)
            content_type = m.from_file(tmp.name)
        except Exception:
            content_type = f.content_type or 'application/octet-stream'

        # scan with clamd
        try:
            scan = scan_file_with_clamd(tmp.name)
        except Exception as e:
            # scanning error — quarantine and fail closed
            qname = os.path.join(QUARANTINE_DIR, f"{uuid.uuid4().hex}_{os.path.basename(tmp.name)}")
            try:
                shutil.move(tmp.name, qname)
            except Exception:
                # best-effort cleanup: try unlink, but swallow errors
                try:
                    if os.path.exists(tmp.name):
                        os.unlink(tmp.name)
                except Exception:
                    pass
            return jsonify({'error': 'scanning failed', 'details': str(e)}), 500

        if scan.get('status') == 'FOUND':
            # move to quarantine
            qname = os.path.join(QUARANTINE_DIR, f"{uuid.uuid4().hex}_{os.path.basename(tmp.name)}")
            try:
                shutil.move(tmp.name, qname)
            except Exception:
                try:
                    if os.path.exists(tmp.name):
                        os.unlink(tmp.name)
                except Exception:
                    pass
            # create metadata record with infected status
            sess = db_session()
            storage_key = f"quarantine/{uuid.uuid4().hex}"
            file_rec = File(owner_id=user_id, filename=filename, content_type=content_type,
                            size=total, storage_key=storage_key, sha256=None, scan_status='infected')
            sess.add(file_rec)
            sess.commit()
            return jsonify({'error': 'file infected', 'signature': scan.get('signature')}), 400

        # clean — compute sha256 and upload to R2 (preferred) or move to local uploads
        h = hashlib.sha256()
        with open(tmp.name, 'rb') as fh:
            for chunk in iter(lambda: fh.read(8192), b''):
                h.update(chunk)
        sha256 = h.hexdigest()
        storage_key = f"uploads/{uuid.uuid4().hex}_{secure_filename(filename)}"
        # try uploading to R2
        uploaded_to_r2 = False
        try:
            with open(tmp.name, 'rb') as fh:
                r2.upload_fileobj(fh, storage_key, content_type=content_type)
            uploaded_to_r2 = True
        except Exception:
            # fallback to local storage
            dest_path = os.path.join(UPLOAD_DIR, os.path.basename(storage_key))
            try:
                shutil.move(tmp.name, dest_path)
            except Exception:
                try:
                    shutil.copyfile(tmp.name, dest_path)
                    os.unlink(tmp.name)
                except Exception as e:
                    try:
                        if os.path.exists(tmp.name):
                            os.unlink(tmp.name)
                    except Exception:
                        pass
                    return jsonify({'error': 'storage failed', 'details': str(e)}), 500

        # persist metadata
        sess = db_session()
        file_rec = File(owner_id=user_id, filename=filename, content_type=content_type,
                        size=total, storage_key=storage_key, sha256=sha256, scan_status='clean')
        sess.add(file_rec)
        sess.commit()

        return jsonify({'id': file_rec.id, 'filename': filename, 'sha256': sha256, 'scan_status': 'clean'}), 201

    finally:
        # ensure temp file removal if still exists
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except Exception:
            pass



@files_bp.route('/files/<int:file_id>', methods=['GET'])
def get_file(file_id: int):
    # return a JSON containing a presigned URL or a download endpoint
    sess = db_session()
    file_rec = sess.get(File, file_id)
    if not file_rec:
        return jsonify({'error': 'not found'}), 404
    # quick auth: only owner may fetch
    user_id = session.get('user_id')
    if user_id != file_rec.owner_id:
        return jsonify({'error': 'forbidden'}), 403

    # If file stored in R2, return a presigned URL
    if file_rec.storage_key and file_rec.storage_key.startswith('uploads/'):
        try:
            url = r2.generate_presigned_url(file_rec.storage_key)
            return jsonify({'url': url}), 200
        except Exception:
            # fallback to local endpoint
            return jsonify({'url': f'/api/files/{file_id}/download'}), 200
    return jsonify({'url': f'/api/files/{file_id}/download'}), 200


@files_bp.route('/files/<int:file_id>/share', methods=['POST'])
def create_share(file_id: int):
    """Create a public share for a file. Body may include `expires_in` (seconds) and `max_uses` (int)."""
    sess = db_session()
    file_rec = sess.get(File, file_id)
    if not file_rec:
        return jsonify({'error': 'not found'}), 404
    user_id = session.get('user_id')
    if user_id != file_rec.owner_id:
        return jsonify({'error': 'forbidden'}), 403

    data = request.get_json() or {}
    # validate schema: expires_in (optional, integer >=1), max_uses (optional, integer >=1)
    schema = {
        'type': 'object',
        'properties': {
            'expires_in': {'type': 'integer', 'minimum': 1},
            'max_uses': {'type': 'integer', 'minimum': 1}
        },
        'additionalProperties': False
    }
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=schema)
    except ImportError:
        # fallback: basic checks
        if 'expires_in' in data:
            try:
                if int(data['expires_in']) < 1:
                    raise ValueError()
            except Exception:
                return jsonify({'error': 'expires_in must be integer >= 1'}), 400
        if 'max_uses' in data:
            try:
                if int(data['max_uses']) < 1:
                    raise ValueError()
            except Exception:
                return jsonify({'error': 'max_uses must be integer >= 1'}), 400
    except jsonschema.ValidationError as ve:
        return jsonify({'error': 'validation error', 'details': ve.message}), 400

    expires_in = data.get('expires_in')
    max_uses = data.get('max_uses')

    token = secrets.token_urlsafe(24)
    expires_at = None
    if expires_in:
        try:
            expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
        except Exception:
            pass

    share = FileShare(file_id=file_rec.id, token=token, created_by=user_id, expires_at=expires_at, max_uses=(int(max_uses) if max_uses else None))
    sess.add(share)
    sess.commit()

    share_url = f"/s/{token}"
    return jsonify({'share_url': share_url, 'token': token, 'expires_at': expires_at.isoformat() if expires_at else None}), 201


@files_bp.route('/shares', methods=['GET'])
def list_shares():
    sess = db_session()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'authentication required'}), 401
    shares = sess.query(FileShare).filter_by(created_by=user_id).all()
    out = []
    for s in shares:
        out.append({'token': s.token, 'file_id': s.file_id, 'expires_at': s.expires_at.isoformat() if s.expires_at else None, 'uses': s.uses, 'max_uses': s.max_uses, 'active': s.is_active()})
    return jsonify(out), 200


@files_bp.route('/shares/<string:token>', methods=['DELETE'])
def revoke_share(token: str):
    sess = db_session()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'authentication required'}), 401
    share = sess.query(FileShare).filter_by(token=token).one_or_none()
    if not share:
        return jsonify({'error': 'not found'}), 404
    if share.created_by != user_id:
        return jsonify({'error': 'forbidden'}), 403
    sess.delete(share)
    sess.commit()
    return jsonify({'status': 'revoked'}), 200


# public share endpoint moved to app/shares.py (registered at root as /s/<token>)


@files_bp.route('/files/<int:file_id>/download', methods=['GET'])
def download_file(file_id: int):
    sess = db_session()
    file_rec = sess.get(File, file_id)
    if not file_rec:
        return jsonify({'error': 'not found'}), 404
    user_id = session.get('user_id')
    if user_id != file_rec.owner_id:
        return jsonify({'error': 'forbidden'}), 403

    # prefer streaming from R2 via presigned URL
    if file_rec.storage_key and file_rec.storage_key.startswith('uploads/'):
        try:
            url = r2.generate_presigned_url(file_rec.storage_key)
            return jsonify({'url': url}), 200
        except Exception:
            # fallback to local streaming
            pass
    local_path = os.path.join(UPLOAD_DIR, os.path.basename(file_rec.storage_key))
    if not os.path.exists(local_path):
        return jsonify({'error': 'file missing'}), 410
    from flask import send_file
    return send_file(local_path, as_attachment=True, download_name=file_rec.filename)


@files_bp.route('/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id: int):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'authentication required'}), 401

    sess = db_session()
    file_rec = sess.get(File, file_id)
    if not file_rec:
        current_app.logger.info('delete: file not found', extra={'file_id': file_id, 'user_id': user_id})
        return jsonify({'error': 'not found'}), 404
    if user_id != file_rec.owner_id:
        current_app.logger.warning('delete: forbidden', extra={'file_id': file_id, 'user_id': user_id, 'owner_id': file_rec.owner_id})
        return jsonify({'error': 'forbidden'}), 403

    # soft-delete: mark in DB and remove local object
    try:
        current_app.logger.info('delete: initiating', extra={'file_id': file_id, 'user_id': user_id})
        # move/delete from R2 or local storage
        try:
            if file_rec.storage_key and file_rec.storage_key.startswith('uploads/'):
                # attempt to delete from R2
                try:
                    r2.delete_object(file_rec.storage_key)
                except Exception:
                    # ignore R2 deletion errors, fallback to local
                    current_app.logger.exception('delete: r2.delete_object failed', exc_info=True)
                    pass
            src = os.path.join(UPLOAD_DIR, os.path.basename(file_rec.storage_key))
            if os.path.exists(src):
                dst = os.path.join(QUARANTINE_DIR, f"deleted_{uuid.uuid4().hex}_{os.path.basename(src)}")
                try:
                    shutil.move(src, dst)
                except Exception:
                    try:
                        shutil.copyfile(src, dst)
                        os.unlink(src)
                    except Exception:
                        current_app.logger.exception('delete: local file move failed', exc_info=True)
                        pass
        except Exception:
            # ignore storage-level errors during delete (best-effort)
            current_app.logger.exception('delete: storage-level error', exc_info=True)
            pass

        file_rec.scan_status = 'deleted'
        sess.add(file_rec)
        # audit
        try:
            al = AuditLog(user_id=user_id, action='delete', object_type='file', object_id=str(file_rec.id), ip_address=request.remote_addr, details=f'deleted by user')
            sess.add(al)
        except Exception:
            current_app.logger.exception('delete: audit log failed', exc_info=True)

        sess.commit()
        current_app.logger.info('delete: success', extra={'file_id': file_id, 'user_id': user_id})
        return jsonify({'status': 'deleted'}), 200
    except Exception as e:
        sess.rollback()
        current_app.logger.exception('delete: unexpected error', exc_info=True)
        return jsonify({'error': 'delete failed', 'details': str(e)}), 500
