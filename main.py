from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer
from okta_jwt.jwt import validate_token as validate_locally
from starlette.config import Config

# Load environment variables
config = Config('.env')

app = FastAPI()

# Define the auth scheme and access token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# Validate the token using Okta JWT library 
def validate(token: str = Depends(oauth2_scheme)):
    try:
        res = validate_locally(
            token,
            config('OKTA_ISSUER'), 
            config('OKTA_AUDIENCE'),
            config('OKTA_CLIENT_ID')
        )
        return bool(res)
    except Exception:
        raise HTTPException(status_code=403)

# Protected route that requires valid token
@app.get('/hello')
def hello(valid: bool = Depends(validate)):
    return {"message": "Hello World!"}