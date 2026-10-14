from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from .verifier import TokenVerifier, error_detail


class AuthDependency(TokenVerifier):
    def __call__(
        self,
        credentials: HTTPAuthorizationCredentials = Security(HTTPBearer()),
    ):
        try:
            return self.verify_token(credentials.credentials)
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=401,
                detail=error_detail(e),
                headers={"WWW-Authenticate": "Bearer"},
            )
