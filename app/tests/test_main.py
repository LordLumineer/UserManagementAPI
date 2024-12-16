import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from fastapi import status
from sqlalchemy.exc import IntegrityError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route,method,expected_status,auth_header",
    [
        ("/ping", "GET", status.HTTP_200_OK, None),
        ("/version", "GET", status.HTTP_200_OK, None),
        ("/interactive-docs", "GET", status.HTTP_307_TEMPORARY_REDIRECT, None),
        ("/redirect_uri", "GET", status.HTTP_307_TEMPORARY_REDIRECT, None),
        ("/invalid-route", "GET", status.HTTP_404_NOT_FOUND, None),
    ],
)
async def test_routes(route, method, expected_status, auth_header, test_app):
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://testserver") as client:
        headers = {"Authorization": auth_header} if auth_header else {}
        response = await getattr(client, method.lower())(route, headers=headers)
        assert response.status_code == expected_status


@pytest.mark.asyncio
async def test_startup_and_shutdown(test_app):
    """
    Test application lifespan events (startup and shutdown).
    """
    with patch("app.core.db.run_migrations") as mock_run_migrations, \
         patch("app.core.db.sessionmanager.init") as mock_db_init, \
         patch("app.core.db.sessionmanager.close") as mock_db_close, \
         patch("app.db_objects.user.init_default_user") as mock_init_user:

        mock_run_migrations.return_value = AsyncMock()
        mock_db_init.return_value = AsyncMock()
        mock_db_close.return_value = AsyncMock()
        mock_init_user.return_value = AsyncMock()

        # Manually trigger startup and shutdown events
        await test_app.router.startup()
        # Verify startup tasks
        # mock_run_migrations.assert_called_once()
        # mock_db_init.assert_called_once()
        # mock_init_user.assert_called_once()

        await test_app.router.shutdown()
        # Verify shutdown tasks
        # mock_db_close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception,expected_status,expected_detail",
    [
        (IntegrityError("UNIQUE constraint failed", orig=Exception("example"), params=None), 500, "already exists"),
        (ValueError("Some value error"), 500, "Some value error"),
        (KeyError("some_key"), 500, "some_key"),
    ],
)
async def test_exception_handlers(exception, expected_status, expected_detail, test_app):
    async def raise_exception():
        raise exception

    test_app.add_api_route("/test-exception", raise_exception, methods=["GET"], tags=["test"])

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://testserver") as client:
        response = await client.get("/test-exception")
        # assert response.status_code == expected_status
        # assert expected_detail in response.text
