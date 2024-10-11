from datetime import datetime, timezone
import smtplib
import ssl
from email.mime.text import MIMEText
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Template
from mailjet_rest import Client

from app.core.config import settings, logger


async def send_MJ_email(recipients: list[str] | str, subject: str, html_content: str):
    """
    Send an email using the Mailjet API

    :params recipient str: The email address of the recipient
    :params subject str: The subject of the email
    :params html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    if isinstance(recipients, str):
        recipients = [recipients]
    mailjet = Client(auth=(settings.MJ_APIKEY_PUBLIC,
                           settings.MJ_APIKEY_PRIVATE), version='v3.1')
    data = {
        'Messages': []
    }
    for recipient in recipients:
        data["Messages"].append(
            {
                "From": {
                    "Email": settings.MJ_SENDER_EMAIL,
                    "Name": settings.PROJECT_NAME
                },
                "To": [
                    {
                        "Email": recipient
                    }
                ],
                "Subject": subject,
                "HTMLPart": html_content
            }
        )
    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        logger.info("Email Sent to %s from %s", recipients, settings.MJ_SENDER_EMAIL) # TODO debug
        return HTMLResponse(content="Test Email Sent", status_code=200)
    logger.error("Failed to send email to %s", recipients)
    logger.error(result.json())
    raise HTTPException(
        status_code=500, detail=f"Failed to send email. {result.json()}")


async def send_smtp_email(recipients: list[str] | str, subject: str, html_content: str):
    """
    Send an email using the SMTP protocol

    :param recipient str: The email address of the recipient
    :param subject str: The subject of the email
    :param html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    if isinstance(recipients, str):
        recipients = [recipients]
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host=settings.SMTP_HOST, port=settings.SMTP_PORT) as server:
            server.ehlo()
            if settings.SMTP_TLS:
                server.starttls(context=context)
                server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            for recipient in recipients:
                html_message = MIMEText(html_content, "html")
                html_message["Subject"] = subject
                html_message["From"] = f"{settings.PROJECT_NAME} <{settings.SMTP_SENDER_EMAIL}>"
                html_message["To"] = recipient
                server.sendmail(settings.SMTP_USER, recipient,
                                html_message.as_string())
            server.quit()
        logger.info("Email Sent to %s from %s", recipients, settings.SMTP_SENDER_EMAIL) # TODO debug
        return HTMLResponse(content="Test Email Sent", status_code=200)
    except Exception as e:
        logger.error("Failed to send email to %s", recipients)
        logger.error(e)
        raise HTTPException(
            status_code=500, detail=f"Failed to send email. {e}") from e


async def send_email(recipients: str, subject: str, html_content: str):
    """
    Send an email using the chosen email method

    :param recipient str: The email address of the recipient
    :param subject str: The subject of the email
    :param html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    match settings.EMAIL_METHOD:
        case "smtp":
            logger.info("Email sent via SMTP") # TODO debug
            return await send_smtp_email(recipients, subject, html_content)
        case "mj":
            logger.info("Email sent via MailJet API") # TODO debug
            return await send_MJ_email(recipients, subject, html_content)
        case "none":
            logger.warning("Email Method is set to 'none', NO EMAIL SENT")
            return HTMLResponse(content="No Email Sent", status_code=200)
        case _:
            logger.critical("Invalid Email Method")
            raise HTTPException(status_code=500, detail="Invalid Email Method")


async def send_test_email(recipient: str):
    """
    Send a test email to the given recipient using the chosen email method

    :param recipient str: The email address of the recipient
    :return bool: True if the email was sent successfully, False otherwise
    """
    with open("./templates/html/test_email.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    # TODO: UPDATE CONTEXT
    context = {
        "ENDPOINT": "/send-test-email/test/todo",
        "PARAMS": "?test=123456789&token=123456789",
        # SAME on all emails
        "PROJECT_NAME": settings.PROJECT_NAME,
        "BASE_URL": settings.BASE_URL,
        "API_URL": settings.API_STR,
        # f"{settings.BASE_URL}{settings.API_STR}/static/logo.png",
        "LOGO_URL": "https://picsum.photos/500/300",
        "COPYRIGHT_YEAR": datetime.now(timezone.utc).year,
        "PRIVACY_ENDPOINT": "/privacy",
        "TERMS_ENDPOINT": "/terms"
    }
    html = template.render(context)
    logger.info("Testing Email to %s", recipient)
    return await send_email(recipient, "Test Email", html)
