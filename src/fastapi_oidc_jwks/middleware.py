from typing import Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware
import jwt

from .verifier import TokenVerifier, error_detail


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        jwks_url: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        super().__init__(app)
        self.verifier = TokenVerifier(jwks_url, issuer=issuer, audience=audience)

    async def dispatch(self, request: Request, call_next):

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
            request.state.user = self.verifier.verify_token(token)

        except jwt.PyJWTError as e:
            return JSONResponse(
                {"detail": error_detail(e)},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)
