from typing import Iterable, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
import jwt

from .verifier import TokenVerifier, error_response


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        jwks_url: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        exclude_paths: Iterable[str] = (),
    ):
        super().__init__(app)
        self.verifier = TokenVerifier(jwks_url, issuer=issuer, audience=audience)
        # Paths served without authentication, e.g. ["/docs", "/openapi.json"]
        self.exclude_paths = set(exclude_paths)

    async def dispatch(self, request: Request, call_next):

        # Browsers send CORS preflight requests without the Authorization header
        if request.method == "OPTIONS" or request.url.path in self.exclude_paths:
            return await call_next(request)

        auth: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(auth)

        if not token or scheme.lower() != "bearer":
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            # Attach user claims to request state
            # In a thread: fetching the JWKS (when not cached) is a blocking HTTP request
            request.state.user = await run_in_threadpool(self.verifier.verify_token, token)

        except jwt.PyJWTError as e:
            status_code, detail = error_response(e)
            return JSONResponse(
                {"detail": detail},
                status_code=status_code,
                headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
            )

        return await call_next(request)
