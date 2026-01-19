# core/email_utils.py
import os
import requests

SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
DEFAULT_FROM = os.environ.get("DEFAULT_FROM_EMAIL", "noreply@gapypay.com")

def send_via_sendgrid(subject: str, plain_text: str, to_email: str):


    payload = {
        "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
        "from": {"email": DEFAULT_FROM},
        "content": [{"type": "text/plain", "value": plain_text}],
    }
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = requests.post(SENDGRID_API_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp

# core/util.py
# core/util.py (dev/debug version)
import logging
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

logger = logging.getLogger(__name__)

def send_verification_email(to_email: str, verify_url: str, recipient_name: str = "") -> bool:
    subject = "Verify your email for VPay"
    html = f"""
      <p>Hi {recipient_name or ''},</p>
      <p>Click the button below to verify your email address for VPay. This link expires in 24 hours.</p>
      <p><a href="{verify_url}" style="display:inline-block;padding:10px 18px;background:#f59e0b;color:#fff;border-radius:6px;text-decoration:none;">Verify email</a></p>
      <p>If you did not request this, ignore this email.</p>
    """

    # basic local validation
    if not settings.SENDGRID_API_KEY:
        logger.error("Missing SENDGRID_API_KEY in settings")
        return False
    if not settings.DEFAULT_FROM_EMAIL:
        logger.error("Missing DEFAULT_FROM_EMAIL in settings")
        return False
    if not to_email or "@" not in to_email:
        logger.error("Invalid recipient email: %r", to_email)
        return False

    message = Mail(
        from_email=settings.DEFAULT_FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=html,
    )

    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        resp = sg.send(message)
        logger.info("SendGrid sent: status=%s", getattr(resp, "status_code", resp))
        return True
    except Exception as exc:
        # SendGrid exceptions often expose a body with details; log everything
        logger.exception("SendGrid error while sending verification email: %r", exc)
        # Try to print more info if present (safely)
        try:
            # some exceptions are HTTPError with a .body or .response attribute
            body = getattr(exc, "body", None) or getattr(exc, "response", None)
            logger.error("SendGrid exception body/response: %r", body)
        except Exception:
            pass
        return False
