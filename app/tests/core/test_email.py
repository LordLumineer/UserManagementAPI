
from unittest.mock import patch
import pytest
from smtplib import SMTPException
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from mailjet_rest.client import ApiError

from app.core.email import (
    send_mj_email,
    send_smtp_email,
    send_email,
    send_test_email,
    send_validation_email,
    send_otp_email,
    send_reset_password_email,
    smtp_emails_verifications
)


@pytest.mark.parametrize("recipients, subject, html_content, expected_status", [
    ("test@example.com", "Single Recipient", "<p>Test Content</p>", 200),
    (["test1@example.com", "test2@example.com"],
     "Multiple Recipients", "<p>Test Content</p>", 200),
    (["invalid_email"], "Invalid Recipient", "<p>Test Content</p>", 500),
])
@pytest.mark.parametrize("client_error", [False, True])
@patch("app.core.email.Client")
@patch("app.core.email.logger")
def test_send_mj_email(mock_logger, mock_client, recipients, subject, html_content, expected_status, client_error):
    if not client_error:
        mock_client.return_value.send.create.return_value.status_code = expected_status
        if expected_status == 200:
            response = send_mj_email(recipients, subject, html_content)
            assert isinstance(response, HTMLResponse)
            assert response.status_code == expected_status
            mock_logger.info.assert_called()
        else:
            with pytest.raises(HTTPException):
                send_mj_email(recipients, subject, html_content)
                mock_logger.error.assert_called()
                mock_logger.critical.assert_not_called()
    else:
        with pytest.raises(HTTPException):
            mock_client.side_effect = ApiError("Error")
            send_mj_email(recipients, subject, html_content)
            mock_logger.error.assert_called()
            mock_logger.critical.assert_called()


@pytest.mark.parametrize("recipients, subject, html_content, expected_status", [
    ("test@example.com", "Single Recipient", "<p>Test Content</p>", 200),
    (["test1@example.com", "test2@example.com"],
     "Multiple Recipients", "<p>Test Content</p>", 200),
    (["invalid_email"], "Invalid Recipient", "<p>Test Content</p>", 500),
])
@pytest.mark.parametrize("client_error", [False, True])
@patch("app.core.email.smtplib.SMTP")
@patch("app.core.email.ssl.create_default_context")
@patch("app.core.email.smtp_emails_verifications")
@patch("app.core.email.logger")
def test_send_smtp_email(mock_logger, mock_verifications, mock_ssl, mock_smtp, recipients, subject, html_content, expected_status, client_error):
    # We don't test the verification process here check the test_smtp_mail_verification.py
    mock_verifications.return_value = recipients
    if not client_error:
        if expected_status == 200:
            mock_smtp.return_value.__enter__.return_value.sendmail.return_value = None
            response = send_smtp_email(recipients, subject, html_content)
            assert isinstance(response, HTMLResponse)
            assert response.status_code == expected_status
            mock_logger.info.assert_called()
        else:
            with pytest.raises(HTTPException):
                mock_smtp.return_value.sendmail.return_value = "Error"
                # with patch("app.core.email.smtplib.SMTP.sendmail", side_effect=SMTPException("Error")):
                send_smtp_email(recipients, subject, html_content)
                mock_logger.error.assert_called()
                mock_logger.critical.assert_not_called()
    else:
        with pytest.raises(HTTPException):
            mock_smtp.side_effect = SMTPException("Error")
            send_smtp_email(recipients, subject, html_content)
            mock_logger.error.assert_called()
            mock_logger.critical.assert_called()


@pytest.mark.parametrize("sender_email, recipients, smtp_responses, expected_exception, expected_valid_recipients", [
    ("valid_sender@example.com", ["valid_recipient@example.com"],
     [(250, "OK"), (250, "OK")], None, ["valid_recipient@example.com"]),
    ("invalid_sender@example.com", ["valid_recipient@example.com"],
     [(550, "Invalid sender"), (250, "OK")], HTTPException, []),
    ("valid_sender@example.com", ["invalid_recipient@example.com"],
     [(250, "OK"), (550, "Invalid recipient")], HTTPException, []),
    ("valid_sender@example.com", ["valid_recipient1@example.com", "invalid_recipient@example.com"], [
     (250, "OK"), (250, "OK"), (550, "Invalid recipient")], None, ["valid_recipient1@example.com"]),
])
@patch("app.core.email.logger")
@patch("app.core.email.smtplib.SMTP")
def test_smtp_emails_verifications(mock_smtp, mock_logger, sender_email, recipients, smtp_responses, expected_exception, expected_valid_recipients):
    smtp_instance = mock_smtp.return_value.__enter__.return_value
    smtp_instance.verify.side_effect = smtp_responses
    if expected_exception:
        with pytest.raises(expected_exception):
            smtp_emails_verifications(smtp_instance, sender_email, recipients)
    else:
        valid_recipients = smtp_emails_verifications(
            smtp_instance, sender_email, recipients)
        assert valid_recipients == expected_valid_recipients
    smtp_instance.verify.assert_any_call(sender_email)
    if smtp_responses[0][0] == 250:
        for recipient in recipients:
            smtp_instance.verify.assert_any_call(recipient)


@pytest.mark.parametrize("mock_settings", [
    {"EMAIL_METHOD": "mj"},
    {"EMAIL_METHOD": "smtp"},
    {"EMAIL_METHOD": "none"},
    {"EMAIL_METHOD": "invalid"},
], indirect=True)
@patch("app.core.email.send_smtp_email")
@patch("app.core.email.send_mj_email")
@patch("app.core.email.logger")
@patch("app.core.email.render_html_template")
def test_send_email(
    mock_render_html_template,
    mock_logger,
    mock_send_mj_email,
    mock_send_smtp_email,
    mock_settings
):
    recipients = ["test@example.com"]
    subject = "Test Subject"
    html_content = "<p>Test Content</p>"
    mock_render_html_template.return_value = html_content
    match mock_settings.EMAIL_METHOD:
        case "mj":
            mock_send_mj_email.return_value = HTMLResponse(status_code=200)
            send_email(recipients, subject, html_content)
            mock_send_mj_email.assert_called()
            mock_logger.debug.assert_called()
        case "smtp":
            mock_send_smtp_email.return_value = HTMLResponse(
                status_code=200)
            send_email(recipients, subject, html_content)
            mock_send_smtp_email.assert_called()
            mock_logger.debug.assert_called()
        case "none":
            response = send_email(recipients, subject, html_content)
            assert isinstance(response, HTMLResponse)
            assert response.status_code == 200
            assert response.body == b"No Email Sent"
            mock_logger.warning.assert_called()
        case _:
            with pytest.raises(HTTPException):
                send_email(recipients, subject, html_content)
                mock_logger.critical.assert_called()
