from typing import Any, Dict, Optional, Tuple
import jwt
from jwt.exceptions import PyJWKClientConnectionError
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


def error_response(error: jwt.PyJWTError) -> Tuple[int, str]:
    # HTTP status code and detail for a verification error
    if isinstance(error, PyJWKClientConnectionError):
        # Not the token's fault: the JWKS could not be fetched
        return 503, "Identity provider unreachable"
    if isinstance(error, jwt.ExpiredSignatureError):
        return 401, "Token expired"
    if isinstance(error, jwt.InvalidAudienceError):
        return 401, "Invalid audience"
    if isinstance(error, jwt.InvalidIssuerError):
        return 401, "Invalid issuer"
    return 401, f"Invalid token: {str(error)}"
