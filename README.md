# FastAPI OIDC JWKS

A FastAPI dependency used to verify a user's OAuth access token with JWKS.

## Installation

```bash
pip install fastapi-oidc-jwks
```

## Usage example

```python
from fastapi import FastAPI, APIRouter, Depends
from fastapi_oidc_jwks import AuthDependency

app = FastAPI()

auth = AuthDependency("Your OIDC provider's JWKS URI here")

router = APIRouter(dependencies=[Depends(auth)])

@router.get("/user")
async def handle(user: dict = Depends(auth)):
    return {"user": user}

app.include_router(router)
```

## Options

`AuthDependency(jwks_uri, issuer=None, audience=None)`: the token's `iss` and `aud` claims are only checked when `issuer` and `audience` are set. With Keycloak, `issuer` is the realm's URL (e.g. `https://keycloak.example.com/realms/myrealm`).

Responses:
- `401` if the token is missing, invalid, expired or has no `exp` claim
- `503` if the JWKS can't be fetched from the identity provider

## Verifying a token outside HTTP requests

`verify_token` returns the token's claims, or raises `jwt.PyJWTError`. For example, to authenticate Socket.IO connections:

```python
import jwt
import socketio

@sio.event
async def connect(sid, environ, data):
    try:
        auth.verify_token((data or {}).get("token") or "")
    except jwt.PyJWTError:
        raise socketio.exceptions.ConnectionRefusedError("unauthorized")
```

`TokenVerifier(jwks_uri, issuer=None, audience=None)` provides `verify_token` without FastAPI's dependency.

## Middleware

`AuthMiddleware` authenticates every request instead, and puts the token's claims in `request.state.user`:

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi_oidc_jwks import AuthMiddleware

app.add_middleware(
    AuthMiddleware,
    jwks_url="Your OIDC provider's JWKS URI here",
    exclude_paths=["/docs", "/openapi.json"],
)
# Added after AuthMiddleware, so that it runs first: 401 responses then get CORS headers too
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_headers=["*"], allow_methods=["*"])
```

`OPTIONS` requests (CORS preflight) and the paths in `exclude_paths` are passed through without authentication.
