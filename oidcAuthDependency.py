from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWKClient

app = FastAPI()


class AuthDependency:
    def __init__(self, jwks_uri: str):
        self.jwks_uri = jwks_uri
        self.jwks_client = PyJWKClient(self.jwks_uri)
        self.audience = None  # For now

    def __call__(
        self,
        credentials: HTTPAuthorizationCredentials = Security(HTTPBearer()),
    ):
        token = credentials.credentials

        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                # issuer=self.issuer, # For now
                options={"verify_aud": self.audience is not None},
            )

        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidAudienceError:
            raise HTTPException(status_code=401, detail="Invalid audience")
        except jwt.InvalidIssuerError:
            raise HTTPException(status_code=401, detail="Invalid issuer")
        except jwt.PyJWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
