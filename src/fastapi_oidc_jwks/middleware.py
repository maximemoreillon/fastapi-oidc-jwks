from typing import Dict, Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware
import jwt
from jwt import PyJWKClient


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        jwks_url: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        super().__init__(app)
        self.jwks_client = PyJWKClient(jwks_url)
        self.issuer = issuer
        self.audience = audience

    async def dispatch(self, request: Request, call_next):

        auth: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(auth)

        if not token or scheme.lower() != "bearer":
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)

        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            payload: Dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_iss": self.issuer is not None,
                    "verify_aud": self.audience is not None,
                },
            )

            # Attach user claims to request state
            request.state.user = payload

        except jwt.ExpiredSignatureError:
            return JSONResponse({"detail": "Token expired"}, status_code=401)
        except jwt.InvalidAudienceError:
            return JSONResponse({"detail": "Invalid audience"}, status_code=401)
        except jwt.InvalidIssuerError:
            return JSONResponse({"detail": "Invalid issuer"}, status_code=401)
        except jwt.PyJWTError as e:
            return JSONResponse({"detail": f"Invalid token: {str(e)}"}, status_code=401)

        return await call_next(request)
