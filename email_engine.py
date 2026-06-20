import logging
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

logger = logging.getLogger(__name__)


def _config():
    return {
        "host": os.getenv("SMTP_HOST", ""),
        "port": int(os.getenv("SMTP_PORT", "465")),
        "user": os.getenv("SMTP_USER", ""),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "use_ssl": os.getenv("SMTP_USE_SSL", "true").lower() not in ("false", "0", "no"),
        "from_name": os.getenv("SMTP_FROM_NAME", ""),
        "enabled": os.getenv("EMAIL_ENABLED", "false").lower() in ("true", "1", "yes"),
    }


def _is_configured(cfg: dict) -> bool:
    return bool(cfg["host"] and cfg["user"] and cfg["password"])


def send_email(
    to: "list[str] | str",
    subject: str,
    body_html: str,
    body_text: str | None = None,
    attachments: list | None = None,
    cc: list[str] | None = None,
) -> dict:
    sent_at = datetime.now(timezone.utc).isoformat()
    to_list = [to] if isinstance(to, str) else list(to)

    cfg = _config()

    if not cfg["enabled"] or not _is_configured(cfg):
        reason = "EMAIL_ENABLED=false" if not cfg["enabled"] else "SMTP not configured"
        logger.info("email disabled / not configured (%s), skipping send to %s", reason, to_list)
        return {"status": "disabled", "to": to_list, "error": None, "sent_at": sent_at}

    from_addr = cfg["user"]
    from_header = f'{cfg["from_name"]} <{from_addr}>' if cfg["from_name"] else from_addr

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = ", ".join(to_list)
    if cc:
        msg["Cc"] = ", ".join(cc)

    if body_text:
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_html, subtype="html")

    if attachments:
        for attachment in attachments:
            maintype = attachment.get("maintype", "application")
            subtype = attachment.get("subtype", "octet-stream")
            msg.add_attachment(
                attachment["data"],
                maintype=maintype,
                subtype=subtype,
                filename=attachment.get("filename", "attachment"),
            )

    try:
        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"]) as smtp:
                smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(cfg["user"], cfg["password"])
                smtp.send_message(msg)

        logger.info("email sent to %s subject=%r", to_list, subject)
        return {"status": "sent", "to": to_list, "error": None, "sent_at": sent_at}

    except Exception as exc:
        logger.exception("email send failed to %s: %s", to_list, exc)
        return {"status": "error", "to": to_list, "error": str(exc), "sent_at": sent_at}
