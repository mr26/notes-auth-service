import os
import requests
from fastapi import FastAPI, HTTPException, Header, Depends
from typing import Optional
import jwt
from jwt import PyJWKClient
from pydantic import BaseModel
import mysql.connector
from mysql.connector import pooling
import logging


# ---------- CONFIG ----------
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
REGION = os.environ.get("AWS_REGION", "us-east-1")
COGNITO_JWKS_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
AUTH_GATEWAY_URL = os.environ.get("AUTH_GATEWAY_URL", "http://auth-gateway:8000/activity")

# Database config
DB_HOST = os.environ["DB_HOST"]
DB_PORT = os.environ.get("DB_PORT", "3306")
DB_NAME = os.environ["DB_NAME"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

app = FastAPI(title="Notes Service", version="1.0")
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Connection pool
db_pool = None


# ---------- DATABASE ----------
def get_db_pool():
    global db_pool
    if db_pool is None:
        db_pool = pooling.MySQLConnectionPool(
            pool_name="notes_pool",
            pool_size=5,
            host=DB_HOST,
            port=int(DB_PORT),
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
    return db_pool


def get_db_connection():
    return get_db_pool().get_connection()


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    logger.info("Database initialized")


# Initialize on startup
@app.on_event("startup")
def startup():
    init_db()


# ---------- MODELS ----------
class Note(BaseModel):
    title: str
    content: str


# ---------- JWT VALIDATION ----------
def verify_cognito_token(authorization: Optional[str] = Header(None)):
    logger.info("Verifying Cognito token")
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    try:
        token_type, token = authorization.split()
        if token_type.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid token type")

        jwk_client = PyJWKClient(COGNITO_JWKS_URL)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=None)
        logger.info("Cognito token verified")
        return payload
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# ---------- ROUTES ----------
@app.post("/notes")
def create_note(note: Note, user=Depends(verify_cognito_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO notes (title, content) VALUES (%s, %s)",
        (note.title, note.content)
    )
    note_id = cursor.lastrowid
    conn.commit()
    cursor.close()
    conn.close()

    # Notify Auth Gateway
    try:
        requests.post(AUTH_GATEWAY_URL, json={"note_id": note_id, "status": "created"}, timeout=5)
    except Exception as e:
        logger.warning(f"Failed to notify auth-gateway: {e}")

    return {"id": note_id, "title": note.title, "content": note.content}


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(verify_cognito_token)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, title, content FROM notes WHERE id = %s", (note_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Note not found")

    # Notify Auth Gateway
    try:
        requests.post(AUTH_GATEWAY_URL, json={"note_id": note_id, "status": "read"}, timeout=5)
    except Exception as e:
        logger.warning(f"Failed to notify auth-gateway: {e}")

    return {"id": row["id"], "title": row["title"], "content": row["content"]}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(verify_cognito_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
    deleted = cursor.rowcount
    conn.commit()
    cursor.close()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Note not found")

    # Notify Auth Gateway
    try:
        requests.post(AUTH_GATEWAY_URL, json={"note_id": note_id, "status": "deleted"}, timeout=5)
    except Exception as e:
        logger.warning(f"Failed to notify auth-gateway: {e}")

    return {"status": "deleted", "note_id": note_id}


@app.get("/healthz")
def health():
    # Check DB connectivity
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")
