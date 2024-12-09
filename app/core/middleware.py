"""
Middleware functions for the application.

This module contains the middleware functions for the application. A middleware
function is a function that takes another function and returns a new function that
"wraps" the original function. The new function produced by the middleware is
called instead of the original function when it's called. Middleware functions are
useful for extending the behavior of existing functions in a decoupled way.

The middleware functions in this module are used to enforce feature flags on
routes, to set the CSP header, and to log information about the requests.

"""
import time
from urllib.parse import urlencode
from cachetools import TTLCache
from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route as StarletteAPIRoute

from app.core.config import settings, logger


class FeatureFlagMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce feature flags.

    This middleware enforces feature flags on routes by checking if the feature
    flag exists in the FEATURE_FLAGS dictionary. If the feature flag exists,
    the middleware checks if the user can access the feature by calling the
    can_view_feature function. If the user cannot access the feature, the
    middleware returns a 403 Forbidden response.
        # Check if a custom feature name is set by the decorator
        feature_name = getattr(endpoint_function, "_feature_name", None)
        if not feature_name:
            feature_name = endpoint_function.__name__.upper()

    The middleware also supports custom feature names by setting the
    _feature_name attribute on the route's endpoint function.

    Example:
        from app.core.permissions import feature_flag

        @feature_flag("my_feature")
        def my_endpoint():
            ...

    :param request: The incoming request.
    :param call_next: The next middleware or the endpoint to call.
    :return: The response from the next middleware or the endpoint.
    """
    # pylint: disable=R0903

    async def dispatch(self, request: Request, call_next):
        """Middleware to enforce feature flags."""
        routes = request.scope.get("app").routes
        path = request.scope.get("path")
        route = next(
            (route for route in routes if route.path == path), None)
        if not isinstance(route, StarletteAPIRoute):  # pragma: no cover
            return await call_next(request)
        endpoint_function = route.endpoint

        # Check if a custom feature name is set by the decorator
        feature_name = getattr(endpoint_function, "_feature_name", None)
        if not feature_name:
            feature_name = endpoint_function.__name__.upper()

        # If the feature flag exists, enforce access rules
        from app.core.permissions import FEATURE_FLAGS, can_view_feature  # pylint: disable=C0415
        from app.db_objects.user import get_current_user  # pylint: disable=C0415

        if feature_name in list(FEATURE_FLAGS.keys()):
            user = None
            token = request.headers.get("Authorization")
            if token and token.startswith("Bearer "):
                try:
                    user = get_current_user(token)
                except HTTPException as e:
                    if e.detail != "Token expired":
                        return JSONResponse(
                            status_code=e.status_code,
                            content=jsonable_encoder(e.detail)
                        )
            feature_enabled = can_view_feature(feature_name, user)
            if not feature_enabled:
                return JSONResponse(
                    status_code=403,
                    content=jsonable_encoder({
                        "error": f"Access to feature '{route.endpoint.__name__}:{feature_name}' is denied.",
                        "support": f"{settings.FRONTEND_URL}/support",
                        "contact": settings.CONTACT_EMAIL
                    })
                )
        return await call_next(request)


class RedirectUriMiddleware(BaseHTTPMiddleware):
    """
    Middleware to store redirect URIs in the session.

    If a redirect_uri parameter is present in the query string, it is
    added to the session's redirect_uri list. The parameter is then
    removed from the query string to avoid passing it to the next
    middleware or endpoint.
    """
    # pylint: disable=R0903

    async def dispatch(self, request: Request, call_next):
        """Middleware to store redirect URIs in the session."""
        redirect_uri = request.query_params.get("redirect_uri")
        if redirect_uri:
            uri_list = request.session.get("redirect_uri") or []
            uri_list.append(str(redirect_uri))
            request.session.update({"redirect_uri": uri_list})

            # Create a new scope without the redirect_uri parameter
            query_params = {
                key: value
                for key, value in request.query_params.items()
                if key != "redirect_uri"
            }
            scope = request.scope
            scope["query_string"] = urlencode(query_params).encode("utf-8")
            request = Request(scope, receive=request.receive)
        return await call_next(request)


class GlobalRateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Middleware to rate limit incoming requests.

    This middleware implements IP-based rate limiting. It stores the number
    of requests from each IP address in a Redis cache. If Redis is unavailable,
    it falls back to an in-memory cache.

    The rate limiting is done using a leaky bucket algorithm. The number of
    requests allowed within the window is `max_requests`. The window size is
    `window_seconds` seconds.

    Parameters:
    ----------
    app : FastAPI
        The FastAPI application.
    max_requests : int
        The maximum number of requests allowed within the window.
    window_seconds : int
        The window size in seconds.
    """
    # pylint: disable=R0903

    def __init__(
        self,
        app: FastAPI,
        max_requests: int,
        window_seconds: int,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.cache = TTLCache(maxsize=1000, ttl=window_seconds)

    async def dispatch(self, request: Request, call_next):
        """Middleware to rate limit incoming requests."""
        client_ip = request.client.host
        current_time = time.time()
        redis_client = request.app.state.redis_client

        if redis_client:
            # Redis-based rate limiting
            key = f"rate-limit:{client_ip}"
            try:
                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, self.window_seconds)
                request_count, _ = pipe.execute()

                if request_count > self.max_requests:
                    logger.warning(
                        f"Rate limit exceeded for IP: {client_ip}"
                    )
                    return Response(status_code=429, content="Too Many Requests")

            except ConnectionError:
                # Fallback to in-memory cache if Redis connection fails
                logger.error(
                    "Redis connection lost. Falling back to in-memory cache.")
                redis_client = None  # Disable Redis for subsequent requests
        else:
            # Cache-based rate limiting
            if client_ip not in self.cache:
                self.cache[client_ip] = {
                    'tokens': self.max_requests, 'last_time': current_time}

            client_data = self.cache[client_ip]
            elapsed = current_time - client_data['last_time']
            refill_tokens = min(
                self.max_requests, client_data['tokens'] + elapsed * (self.max_requests / self.window_seconds))
            client_data['tokens'] = refill_tokens
            client_data['last_time'] = current_time

            if client_data['tokens'] < 1:
                logger.warning(
                    f"Rate limit exceeded for IP: {client_ip}"
                )
                return Response(status_code=429, content="Too Many Requests")

            client_data['tokens'] -= 1
            self.cache[client_ip] = client_data
        return await call_next(request)
