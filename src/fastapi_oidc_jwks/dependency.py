from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from .verifier import TokenVerifier, error_response


class AuthDependency(TokenVerifier):
    def __call__(
        self,
        credentials: HTTPAuthorizationCredentials = Security(HTTPBearer()),
    ):
        try:
            return self.verify_token(credentials.credentials)
        except jwt.PyJWTError as e:
            status_code, detail = error_response(e)
            raise HTTPException(
                status_code=status_code,
                detail=detail,
                headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
            )
