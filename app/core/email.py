from datetime import datetime, timezone
import smtplib
import ssl
from email.mime.text import MIMEText
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Template
from mailjet_rest import Client

from app.core.config import settings, logger


async def send_MJ_email(recipient: str, subject: str, html_content: str):
    """
    Send an email using the Mailjet API

    :params recipient str: The email address of the recipient
    :params subject str: The subject of the email
    :params html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    mailjet = Client(auth=(settings.MJ_APIKEY_PUBLIC,
                           settings.MJ_APIKEY_PRIVATE), version='v3.1')
    data = {
        'Messages': [
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
        ]
    }
    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        logger.info(f"Email Sent to {recipient}")
        return True
    logger.error("Failed to send email to %s", recipient)
    logger.error(result.json())
    return False


async def send_smtp_email(receiver: str, subject: str, html_content: str):
    """
    Send an email using the SMTP protocol

    :param receiver str: The email address of the recipient
    :param subject str: The subject of the email
    :param html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    sender = settings.SMTP_USER
    sender_pwd = settings.SMTP_PASSWORD
    smtp_server = settings.SMTP_HOST
    smtp_port = settings.SMTP_PORT

    html_message = MIMEText(html_content, "html")
    html_message["Subject"] = subject
    html_message["From"] = sender
    html_message["To"] = receiver

    context = ssl.create_default_context()

    with smtplib.SMTP(host=smtp_server, port=smtp_port) as server:
        server.ehlo()
        if settings.SMTP_TLS:
            server.starttls(context=context)
            server.ehlo()
        server.login(sender, sender_pwd)
        server.sendmail(sender, receiver, html_message.as_string())
        server.quit()
    # TODO: check logguru logging.success
    logger.info(f"Email Sent to {receiver}")
    return True


async def send_email(receiver: str, subject: str, html_content: str):
    """
    Send an email using the chosen email method

    :param receiver str: The email address of the recipient
    :param subject str: The subject of the email
    :param html_content str: The HTML content of the email
    :return bool: True if the email was sent successfully, False otherwise
    """
    match settings.EMAIL_METHOD:
        case "smtp":
            return await send_smtp_email(receiver, subject, html_content)
        case "mj":
            return await send_MJ_email(receiver, subject, html_content)
        case "none":
            logger.warning("Email Method is set to 'none', NO EMAIL SENT")
            return True
        case _:
            logger.critical("Invalid Email Method")
            raise HTTPException(status_code=500, detail="Invalid Email Method")


async def send_test_email(receiver: str):
    """
    Send a test email to the given receiver using the chosen email method

    :param receiver str: The email address of the recipient
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
    logger.info("Testing Email %s to %s",
                settings.MJ_SENDER_EMAIL, receiver)

    await send_email(receiver, "Test Email", html)
    return HTMLResponse(content="Test Email Sent", status_code=200)
