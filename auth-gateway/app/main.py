import os
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime
from typing import Optional

import boto3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

# OpenTelemetry
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor

# ----------------------------
# OpenTelemetry Setup
# ----------------------------

OTEL_ENDPOINT = os.environ.get(
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "http://otel-collector-opentelemetry-collector.observability.svc.cluster.local:4317"
)

resource = Resource(attributes={SERVICE_NAME: "auth-gateway"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)))
trace.set_tracer_provider(provider)

# Auto-instrument botocore (Cognito, Secrets Manager calls)
BotocoreInstrumentor().instrument()


# ----------------------------
# App & AWS setup
# ----------------------------

app = FastAPI(title="Auth Gateway", version="1.2")

# Auto-instrument FastAPI (all routes automatically traced)
FastAPIInstrumentor.instrument_app(app)

AWS_REGION = os.environ["AWS_REGION"]
CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
SECRET_NAME = os.environ["COGNITO_SECRET_NAME"]

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)
secrets_client = boto3.client("secretsmanager", region_name=AWS_REGION)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-gateway")


# ----------------------------
# Secrets Manager (cached)
# ----------------------------

_client_secret: Optional[str] = None
_client_secret_ts = 0

def get_client_secret(ttl: int = 300) -> Optional[str]:
    global _client_secret, _client_secret_ts

    if _client_secret and time.time() - _client_secret_ts < ttl:
        return _client_secret

    try:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        secret = json.loads(response["SecretString"])["client_secret"]
    except Exception:
        logger.exception("Failed to fetch Cognito client secret")
        raise HTTPException(status_code=500, detail="Auth configuration error")

    _client_secret = secret
    _client_secret_ts = time.time()
    return secret


# ----------------------------
# Helpers
# ----------------------------

def calculate_secret_hash(username: str) -> Optional[str]:
    client_secret = get_client_secret()
    if not client_secret:
        return None

    message = username + CLIENT_ID
    digest = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return base64.b64encode(digest).decode()


# ----------------------------
# Request models
# ----------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    username: str
    new_password: str
    session: str


class ActivityEvent(BaseModel):
    note_id: int
    status: str


# ----------------------------
# Routes
# ----------------------------

@app.post("/login")
def login(req: LoginRequest):
    auth_params = {
        "USERNAME": req.username,
        "PASSWORD": req.password,
    }

    secret_hash = calculate_secret_hash(req.username)
    if secret_hash:
        auth_params["SECRET_HASH"] = secret_hash

    try:
        response = cognito.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=CLIENT_ID,
            AuthParameters=auth_params,
        )
    except cognito.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    except cognito.exceptions.UserNotFoundException:
        raise HTTPException(status_code=401, detail="User not found")
    except Exception:
        logger.exception("Cognito initiate_auth failed")
        raise HTTPException(status_code=500, detail="Authentication failed")

    if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
        return {
            "challenge": "NEW_PASSWORD_REQUIRED",
            "session": response["Session"],
        }

    auth_result = response["AuthenticationResult"]

    return {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "refresh_token": auth_result.get("RefreshToken"),
        "expires_in": auth_result["ExpiresIn"],
        "token_type": auth_result["TokenType"],
    }


@app.post("/change-password")
def change_password(req: ChangePasswordRequest):
    challenge_responses = {
        "USERNAME": req.username,
        "NEW_PASSWORD": req.new_password,
    }

    secret_hash = calculate_secret_hash(req.username)
    if secret_hash:
        challenge_responses["SECRET_HASH"] = secret_hash

    try:
        response = cognito.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=req.session,
            ChallengeResponses=challenge_responses,
        )
    except Exception:
        logger.exception("Cognito password change failed")
        raise HTTPException(status_code=400, detail="Password change failed")

    auth_result = response["AuthenticationResult"]

    return {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "refresh_token": auth_result.get("RefreshToken"),
        "expires_in": auth_result["ExpiresIn"],
        "token_type": auth_result["TokenType"],
    }


# ----------------------------
# Activity callback
# ----------------------------

@app.post("/activity")
def record_activity(event: ActivityEvent):
    logger.info(
        "activity_event",
        extra={
            "timestamp": datetime.utcnow().isoformat(),
            "event": event.dict(),
        },
    )
    return {"status": "recorded"}


@app.get("/healthz")
def health():
    return {"status": "ok"}
