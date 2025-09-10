from fastapi import FastAPI, APIRouter, Depends
from oidcAuthDependency import AuthDependency
from os import getenv

app = FastAPI()


auth = AuthDependency(getenv("OIDC_JWKS_URI"))


router = APIRouter(
    dependencies=[Depends(auth)],
)


@app.get("/greetings")
async def handle():
    return "Hello world"


@router.get("/user")
async def handle(user: dict = Depends(auth)):
    return {"user": user}


@router.get("/nouser")
async def handle():
    return {"user": None}


app.include_router(router)
