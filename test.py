import json
import logging
import os
import time
import uuid
from contextvars import ContextVar
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import jwt
from jwt.exceptions import InvalidTokenError
from okta_jwt_verifier import AccessTokenVerifier
from starlette.middleware.base import BaseHTTPMiddleware

# Load environment variables
load_dotenv()

# Logging configuration
class StructuredLogger(logging.Logger):
    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False, stacklevel=1):
        if extra is None:
            extra = {}
        extra['timestamp'] = time.time()
        super()._log(level, msg, args, exc_info, extra, stack_info, stacklevel)

logging.setLoggerClass(StructuredLogger)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Custom HTTP bearer class
class CustomHTTPBearer(HTTPBearer):
    async def __call__(self, request: Request):
        try:
            return await super().__call__(request)
        except HTTPException as e:
            if e.status_code == 403:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization header is missing or invalid",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            raise e

# Security scheme for bearer token
security = CustomHTTPBearer()

# List of allowed client IDs
ALLOWED_CLIENT_IDS = os.getenv("ALLOWED_CLIENT_IDS", "").split(",")

# Okta configuration
OKTA_ISSUER = os.getenv("OKTA_ISSUER")
OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE")

# JWT verifier instance
token_verifier = AccessTokenVerifier(OKTA_ISSUER, OKTA_AUDIENCE)

# Create a context variable to store the request ID
request_id_var = ContextVar("request_id", default=None)

# Middleware to add request ID
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        request_id_var.set(request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestIDMiddleware)

# Middleware to log request and response
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    log_dict = {
        "request_id": request.state.request_id,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "process_time_ms": round(process_time, 2)
    }
    logger.info(f"Request processed: {json.dumps(log_dict)}")
    return response

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    request_id = request_id_var.get()
    logger.debug(f"Received token: {token[:10]}...", extra={"request_id": request_id})

    try:
        # Decode the token (without verification) to get the client ID
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        logger.debug("Decoded token", extra={"request_id": request_id, "decoded_token": decoded_token})

        client_id = decoded_token.get("cid") or decoded_token.get("client_id")
        logger.info(f"Extracted client_id: {client_id}", extra={"request_id": request_id})

        if not client_id:
            logger.error("Token does not contain client_id", extra={"request_id": request_id})
            raise HTTPException(status_code=400, detail="Token does not contain client_id")

        logger.debug(f"Allowed client IDs: {ALLOWED_CLIENT_IDS}", extra={"request_id": request_id})

        # Check if the client ID is in the allowed list (case-insensitive)
        if not any(allowed_id.lower() == client_id.lower() for allowed_id in ALLOWED_CLIENT_IDS):
            logger.error(f"Unauthorized client: {client_id}", extra={"request_id": request_id})
            raise HTTPException(status_code=403, detail=f"Unauthorized client: {client_id}")

        # Verify the token with Okta
        try:
            await token_verifier.verify(token)
            logger.info("Token successfully verified with Okta", extra={"request_id": request_id})
        except Exception as okta_error:
            logger.error(f"Okta verification failed: {str(okta_error)}", extra={"request_id": request_id})
            raise HTTPException(status_code=401, detail=f"Okta verification failed: {str(okta_error)}")

        return decoded_token
    except jwt.DecodeError as e:
        logger.error(f"Invalid token format: {str(e)}", extra={"request_id": request_id})
        raise HTTPException(status_code=400, detail="Invalid token format")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {str(e)}", exc_info=True, extra={"request_id": request_id})
        raise HTTPException(status_code=500, detail=f"Unexpected error during token verification")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP exception: {exc.status_code} - {exc.detail}", extra={"request_id": request.state.request_id})
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail or "An error occurred"},
    )

@app.get("/hello")
async def hello_world(request: Request, token: dict = Depends(verify_token)):
    logger.info(f"Hello world request received", extra={"request_id": request.state.request_id})
    return {"message": "Hello, World!"}

@app.get("/public")
async def public_route(request: Request):
    logger.info("Public route accessed", extra={"request_id": request.state.request_id})
    return {"message": "This is a public route"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("test:app", host="0.0.0.0", port=8000, reload=True)



