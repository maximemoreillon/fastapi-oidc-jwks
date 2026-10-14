from typing import Any, Dict, Optional
import jwt
from jwt import PyJWKClient


class TokenVerifier:
    def __init__(
        self,
        jwks_uri: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):

        if not jwks_uri:
            raise Exception("jwks_uri not set")

        self.jwks_uri = jwks_uri
        self.jwks_client = PyJWKClient(self.jwks_uri)
        self.issuer = issuer
        self.audience = audience

    def verify_token(self, token: str) -> Dict[str, Any]:
        # Returns the token's claims, raises jwt.PyJWTError if the token is invalid
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
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


def error_detail(error: jwt.PyJWTError) -> str:
    if isinstance(error, jwt.ExpiredSignatureError):
        return "Token expired"
    if isinstance(error, jwt.InvalidAudienceError):
        return "Invalid audience"
    if isinstance(error, jwt.InvalidIssuerError):
        return "Invalid issuer"
    return f"Invalid token: {str(error)}"
