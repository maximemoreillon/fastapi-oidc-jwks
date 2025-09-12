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
