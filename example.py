from fastapi import FastAPI, APIRouter, Depends
from dotenv import load_dotenv

# from fastapi_oidc_jwks.dependency import AuthDependency
from src.fastapi_oidc_jwks import AuthDependency
from os import getenv

load_dotenv()  # take environment variables

app = FastAPI()


auth = AuthDependency(getenv("OIDC_JWKS_URI"))


router = APIRouter(
    dependencies=[Depends(auth)],
)


@app.get("/")
async def handle():
    return "Hello world"


@router.get("/user")
async def handle(user: dict = Depends(auth)):
    return {"user": user}


@router.get("/nouser")
async def handle():
    return {"user": None}


app.include_router(router)
