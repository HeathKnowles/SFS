import os
import smtplib
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer


def get_serializer(secret_key=None):
    secret = secret_key or os.environ.get('SECRET_KEY', 'dev-secret')
    return URLSafeTimedSerializer(secret)


def send_email(to_email: str, subject: str, body: str):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = os.environ.get('EMAIL_FROM', 'no-reply@example.com')
    msg['To'] = to_email
    msg.set_content(body)

    if smtp_host and smtp_user and smtp_pass:
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
    else:
        # fallback to console for dev
        print('--- send_email fallback ---')
        print('To:', to_email)
        print('Subject:', subject)
        print(body)
        print('---')
