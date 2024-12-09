import pytest
from fastapi import status


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/404",
    "/",
    "/terms",
    "/privacy",
    "/support",
])
async def test_placeholders_page(endpoint, client):
    """Test the /<placeholders> endpoint rendering."""
    response = client.get(endpoint)
    # assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "404 - Page Not Found" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/login",
    "/signin",
    "/otp",
    "/register",
    "/signup",
    "/logout",
    "/reset-password/request",
    "/reset-password/reset",
    "/forgot-password/request",
    "/forgot-password/reset",
])
async def test_backups_page(endpoint, client):
    """Test the /login endpoint rendering."""
    response = client.get(endpoint)
    assert response.status_code == status.HTTP_200_OK
    assert "/auth/" in response.text
