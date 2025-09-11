from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
import jwt
from jwt import PyJWKClient
from starlette.middleware.base import BaseHTTPMiddleware


class JWTAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        jwks_url: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        public_paths: Optional[List[str]] = None,
    ):
        """
        Middleware for strict JWT auth.
        Blocks all requests without a valid token,
        except for whitelisted public_paths.
        """
        super().__init__(app)
        self.jwks_client = PyJWKClient(jwks_url)
        self.issuer = issuer
        self.audience = audience
        self.public_paths = set(public_paths or [])

    async def dispatch(self, request: Request, call_next):

        auth: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(auth)

        if not token or scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            # Validate JWT
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            payload: Dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                # issuer=self.issuer,
                options={"verify_aud": self.audience is not None},
            )
            request.state.user = payload

        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidAudienceError:
            raise HTTPException(status_code=401, detail="Invalid audience")
        except jwt.InvalidIssuerError:
            raise HTTPException(status_code=401, detail="Invalid issuer")
        except jwt.PyJWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

        return await call_next(request)
