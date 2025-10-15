import os
import boto3
from botocore.client import Config

R2_ENDPOINT = os.environ.get('CLOUDFLARE_S3_ENDPOINT')
R2_ACCESS_KEY = os.environ.get('CLOUDFLARE_ACCESS_KEY_ID')
R2_SECRET_KEY = os.environ.get('CLOUDFLARE_SECRET_ACCESS_KEY')
# prefer explicit R2 bucket env var; fall back to sensible alternatives or default to 'sfs'
R2_BUCKET = (
    os.environ.get('CLOUDFLARE_R2_BUCKET')
    or os.environ.get('R2_BUCKET')
    or os.environ.get('CLOUDFLARE_BUCKET')
    or os.environ.get('CLOUDFLARE_BUCKET_NAME')
    or 'sfs'
)


def make_client():
    if not R2_ENDPOINT or not R2_ACCESS_KEY or not R2_SECRET_KEY:
        raise RuntimeError('R2 configuration missing in environment (CLOUDFLARE_S3_ENDPOINT, CLOUDFLARE_ACCESS_KEY_ID, CLOUDFLARE_SECRET_ACCESS_KEY required)')
    endpoint = R2_ENDPOINT
    try:
        # parse and remove path component
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(endpoint)
        if parsed.path and parsed.path not in ('', '/'):
            parsed = parsed._replace(path='')
            endpoint = urlunparse(parsed)
    except Exception:
        # if parsing fails, continue with the provided value
        endpoint = R2_ENDPOINT

    s3 = boto3.client(
        's3',
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        endpoint_url=endpoint,
        config=Config(signature_version='s3v4'),
    )
    return s3


def upload_fileobj(fileobj, key: str, content_type: str = None):
    """Upload a file-like object to R2 under the configured bucket and key."""
    s3 = make_client()
    extra = {}
    if content_type:
        extra['ContentType'] = content_type
    bucket = R2_BUCKET
    if not bucket:
        raise RuntimeError('R2 bucket not configured')
    s3.upload_fileobj(fileobj, bucket, key, ExtraArgs=extra)


def generate_presigned_url(key: str, expires_in: int = 3600):
    s3 = make_client()
    bucket = R2_BUCKET
    if not bucket:
        raise RuntimeError('R2 bucket not configured')
    return s3.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': key}, ExpiresIn=expires_in)


def delete_object(key: str):
    s3 = make_client()
    bucket = R2_BUCKET
    if not bucket:
        raise RuntimeError('R2 bucket not configured')
    return s3.delete_object(Bucket=bucket, Key=key)
