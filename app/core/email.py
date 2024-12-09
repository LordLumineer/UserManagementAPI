"""
Email-related utilities.

This module contains the functions to send emails. It is designed to be
used with FastAPI but can be used with any other Python application. It
can use SMTP or Mailjet to send emails, depending on the EMAIL_METHOD
setting.
"""
from datetime import datetime, timedelta, timezone
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from typing import Literal
from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse
from mailjet_rest import Client

from app.core.config import settings, logger
from app.core.utils import app_path, get_info_from_request, render_html_template


async def send_mj_email(recipients: list[str] | str, subject: str, html_content: str):
    """
    Send an email to a single recipient or a list of recipients using MailJet's API.

    :param list[str] | str recipients: the recipient(s) of the email.
    :param str subject: the subject of the email.
    :param str html_content: the content of the email.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
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
        logger.info(
            f"""Email Sent with MailJet API
            - To {recipients}
            - From {settings.MJ_SENDER_EMAIL}
            - Subject: {subject}""")
        return HTMLResponse(content=f"Subject: {subject} - Email Sent", status_code=200)
    logger.error(f"Failed to send email to {recipients}")
    logger.error(result.json())
    raise HTTPException(
        status_code=500, detail=f"Failed to send email. {result.json()}")


async def send_smtp_email(recipients: list[str] | str, subject: str, html_content: str):
    """
    Send an email to a single recipient or a list of recipients using an SMTP server.

    :param list[str] | str recipients: the recipient(s) of the email.
    :param str subject: the subject of the email.
    :param str html_content: the content of the email.
    :return: an HTMLResponse with a success message if the email is sent successfully,
        otherwise an HTTPException with a 500 status code is raised.
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
                html_message["From"] = f"{settings.PROJECT_NAME} <{
                    settings.SMTP_SENDER_EMAIL}>"
                html_message["To"] = recipient
                server.sendmail(settings.SMTP_USER, recipient,
                                html_message.as_string())
            server.quit()
        logger.info(
            f"""Email Sent with SMTP Server
                - Host: {settings.SMTP_HOST}
                - To {recipients}
                - From {settings.SMTP_SENDER_EMAIL}
                - Subject: {subject}""")
        return HTMLResponse(content=f"Subject: {subject} - Email Sent", status_code=200)
    except Exception as e:
        logger.error(f"Failed to send email to {recipients}")
        logger.error(e)
        raise HTTPException(
            status_code=500, detail=f"Failed to send email. {e}") from e


async def send_email(recipients: list[str], subject: str, html_content: str):
    """
    Send an email to a single recipient or a list of recipients.

    :param list[str] recipients: the recipient(s) of the email.
    :param str subject: the subject of the email.
    :param str html_content: the content of the email.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
    """
    html_content = render_html_template(html_content)

    match settings.EMAIL_METHOD:
        case "smtp":
            logger.debug("Email sent via SMTP")
            return await send_smtp_email(recipients, subject, html_content)
        case "mj":
            logger.debug("Email sent via MailJet API")
            return await send_mj_email(recipients, subject, html_content)
        case "none":
            logger.warning("Email Method is set to 'none', NO EMAIL SENT")
            return HTMLResponse(content="No Email Sent", status_code=200)
        case _:
            logger.critical("Invalid Email Method")
            raise HTTPException(status_code=500, detail="Invalid Email Method")


async def send_test_email(recipient: str):
    """
    Send a test email to a single recipient.

    :param str recipient: the recipient of the email.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
    """
    with open(app_path(os.path.join("app", "templates", "html", "email_test.html")), "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/send-test-email/test/todo",
        "PARAMS": "?test=123456789&token=123456789"
    }
    html = render_html_template(html_content, context)
    logger.debug(f"Testing Email to {recipient}")
    return await send_email(recipient, f"{settings.PROJECT_NAME} - Test Email", html)


async def send_validation_email(recipient: str, token_str: str):
    """
    Send a validation email to a single recipient.

    :param str recipient: the recipient of the email.
    :param str token_str: the token to be used for verification.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
    """
    with open(app_path(os.path.join("app", "templates",
                                    "html", "email_validate.html")), "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/email/verify",
        "PARAMS": f"?token={token_str}"
    }
    html = render_html_template(html_content, context)
    logger.debug(f"Sending Validation Email: {recipient}")
    return await send_email(recipient, f"{settings.PROJECT_NAME} - Activate your account", html)


async def send_otp_email(recipient: str, otp_code: str, request: Request = None):
    """
    Send an email with a one-time password to a single recipient.

    :param str recipient: the recipient of the email.
    :param str otp_code: the one-time password to be sent.
    :param Request request: the request object. 
        If not provided, the email sent will not contain any information about the user's 
        location, device, browser, or IP address.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
    """
    info = get_info_from_request(request)
    with open(app_path(os.path.join("app", "templates", "html", "email_otp.html")), "r", encoding="utf-8") as f:
        html_content = f.read()
    expiration_date = datetime.now(
        timezone.utc) + timedelta(seconds=settings.OTP_EMAIL_INTERVAL)
    context = {
        "LOCATION": info["location"],
        "DEVICE": info["device"],
        "BROWSER": info["browser"],
        "IP_ADDRESS": info["ip_address"],
        "OTP_CODE": otp_code,
        "EXPIRATION_DATE": expiration_date.strftime("%B %d, %Y %H:%M:%S %Z"),
        "RESET_PASSWORD_URL": f"{settings.FRONTEND_URL}/reset-password"
    }
    html = render_html_template(html_content, context)
    logger.debug(f"Sending One-Time Password Email: {recipient}")
    return await send_email(recipient, f"{settings.PROJECT_NAME} - Login Token", html)


async def send_reset_password_email(
        recipient: str,
        token_str: str,
        endpoint: Literal["/reset-password", "/forgot-password/reset-form"],
        request: Request = None):
    """
    Send a reset password email to a single recipient.

    :param str recipient: the recipient of the email.
    :param str token_str: the token to be used for verification.
    :return: an HTMLResponse with a success message if the email is sent successfully, 
        otherwise an HTTPException with a 500 status code is raised.
    """
    info = get_info_from_request(request)
    with open(app_path(os.path.join("app", "templates", "html",
                                    "email_reset_password.html")), "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "LOCATION": info["location"],
        "DEVICE": info["device"],
        "BROWSER": info["browser"],
        "IP_ADDRESS": info["ip_address"],
        "ENDPOINT": endpoint,
        "PARAMS": f"?token={token_str}"
    }
    html = render_html_template(html_content, context)
    logger.debug(f"Sending Reset Password Email: {recipient}")
    return await send_email(recipient, f"{settings.PROJECT_NAME} - Reset your password", html)
