from __future__ import annotations

from urllib.parse import urlparse

from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import (
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route

from analytics_mcp.auth_context import (
    DatabaseTokenVerifier,
    get_app_config,
    get_token_store,
)
from analytics_mcp.oauth_server import oauth_routes


def create_web_app(mcp: Server):
    config = get_app_config()
    store = get_token_store()
    store.init()
    public_host = urlparse(config.server.public_base_url).netloc
    resource_url = AnyHttpUrl(f"{config.server.public_base_url}/mcp")
    session_manager = StreamableHTTPSessionManager(
        app=mcp,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            allowed_hosts=[public_host]
        ),
    )

    return Starlette(
        routes=[
            *oauth_routes(config, store),
            Route(
                "/mcp",
                endpoint=RequireAuthMiddleware(
                    session_manager.handle_request,
                    ["mcp"],
                    build_resource_metadata_url(resource_url),
                ),
            ),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                backend=BearerAuthBackend(DatabaseTokenVerifier(store)),
            ),
            Middleware(AuthContextMiddleware),
        ],
        lifespan=lambda app: session_manager.run(),
        debug=False,
    )


def run_web_app(mcp: Server) -> None:
    import uvicorn

    config = get_app_config()
    uvicorn.run(
        create_web_app(mcp), host=config.server.host, port=config.server.port
    )
