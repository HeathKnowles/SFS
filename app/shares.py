from flask import Blueprint, redirect, jsonify
from .extensions import db_session
from .models.models import FileShare, File
from .storage import r2

shares = Blueprint('shares', __name__)


@shares.route('/s/<string:token>', methods=['GET'])
def public_share(token: str):
    sess = db_session()
    share = sess.query(FileShare).filter_by(token=token).one_or_none()
    if not share:
        return jsonify({'error': 'not found'}), 404
    if not share.is_active():
        return jsonify({'error': 'expired or exhausted'}), 410

    file_rec = sess.get(File, share.file_id)
    if not file_rec:
        return jsonify({'error': 'file not found'}), 404

    # increment uses
    share.uses = (share.uses or 0) + 1
    sess.add(share)
    sess.commit()

    # If stored in R2, generate presigned URL and redirect
    if file_rec.storage_key and file_rec.storage_key.startswith('uploads/'):
        try:
            url = r2.generate_presigned_url(file_rec.storage_key)
            return redirect(url)
        except Exception:
            pass

    # fallback: redirect to API download endpoint
    return redirect(f"/api/files/{file_rec.id}/download")
