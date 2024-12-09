"""
This module contains the API endpoints for the pages of the application.

The pages are static HTML pages that are rendered by the application using
FastAPI's built-in support for HTML templates.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.config import settings
from app.core.utils import render_html_response


router = APIRouter()

# ----- PLACEHOLDER ----- #


@router.get("/404", include_in_schema=False, response_class=HTMLResponse)
def _404(request: Request):
    return render_html_response("page_404.html", request)


@router.get("/", include_in_schema=False, response_class=HTMLResponse)
def _index(request: Request):
    return RedirectResponse(url=request.url_for("_404"))


@router.get("/terms", include_in_schema=False, response_class=HTMLResponse)
def _terms(request: Request):
    return RedirectResponse(url=request.url_for("_404"))


@router.get("/privacy", include_in_schema=False, response_class=HTMLResponse)
def _privacy(request: Request):
    return RedirectResponse(url=request.url_for("_404"))


@router.get("/support", include_in_schema=False, response_class=HTMLResponse)
def _support(request: Request):
    return RedirectResponse(url=request.url_for("_404"))

# ----- BACK UPs ----- #


@router.get("/login", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
@router.get("/signin", tags=["PAGE"], include_in_schema=False, response_class=RedirectResponse)
def _login(request: Request):
    return render_html_response("page_login.html", request)


@router.get("/otp", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _otp(request: Request):
    otp_token = request.session.get("otp_token")
    if not otp_token:
        return RedirectResponse(url=request.url_for("_login"))
    context = {
        "OTP_LENGTH": settings.OTP_LENGTH,
    }
    return render_html_response("page_otp.html", request, context)


@router.get("/register", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
@router.get("/signup", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _signup(request: Request):
    return render_html_response("page_signup.html", request)


@router.get("/logout", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _logout(request: Request):
    return render_html_response("page_logout.html", request)


@router.get("/reset-password/request", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _reset_password_request(request: Request):
    return render_html_response("page_reset-password-request.html", request)


@router.get("/reset-password/reset", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _reset_password_reset(request: Request, token: str | None = None):
    context = {"RESET_TOKEN": token}
    return render_html_response("page_reset-password-reset.html", request, context)


@router.get("/forgot-password/request", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _forgot_password_request(request: Request):
    return render_html_response("page_forgot-password-request.html", request)


@router.get("/forgot-password/reset", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _forgot_password_reset(request: Request, token: str | None = None):
    context = {"RESET_TOKEN": token}
    return render_html_response("page_forgot-password-reset.html", request, context)
