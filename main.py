from fastapi import FastAPI, Query
from datetime import datetime, timedelta
import jwt
import json
import base64
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Initialize app
app = FastAPI()

# Store keys in-memory
KEYS = {}
EXPIRY_DAYS = 1


# Generate an RSA Key Pair
def generate_rsa_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    kid = base64.urlsafe_b64encode(json.dumps({"created_at": str(datetime.utcnow())}).encode()).decode()
    expiry = datetime.utcnow() - timedelta(days=1) if expired else datetime.utcnow() + timedelta(days=EXPIRY_DAYS)
    KEYS[kid] = {"private": private_key, "public": public_key, "expiry": expiry}
    return kid


# Key rotation (Runs every 12 hours)
def key_rotation():
    while True:
        time.sleep(12 * 3600)
        generate_rsa_key()


# Start key rotation thread
threading.Thread(target=key_rotation, daemon=True).start()

# Generate initial valid and expired keys
current_kid = generate_rsa_key()
expired_kid = generate_rsa_key(expired=True)


@app.get("/jwks", status_code=200)
def get_jwks():
    valid_keys = [
        {
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": base64.urlsafe_b64encode(KEYS[kid]["public"].public_numbers().n.to_bytes(256, 'big')).decode(),
            "e": base64.urlsafe_b64encode(KEYS[kid]["public"].public_numbers().e.to_bytes(3, 'big')).decode()
        }
        for kid in KEYS if KEYS[kid]['expiry'] > datetime.utcnow()
    ]
    return {"keys": valid_keys} if valid_keys else {"keys": []}


@app.get("/jwks-expired", status_code=200)
def get_expired_jwks():
    return {"keys": []}  # Ensuring expired keys do not appear in JWKS


@app.post("/auth")
def authenticate(expired: bool = Query(False)):
    global current_kid, expired_kid

    if expired:
        kid = expired_kid
    else:
        kid = current_kid

    private_key = KEYS[kid]["private"]
    exp_time = datetime.utcnow() - timedelta(days=1) if expired else datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({"sub": "user123", "exp": exp_time, "kid": kid}, private_key, algorithm="RS256")
    return {"token": token}


# Ensure at least one valid key exists before startup
generate_rsa_key()

# Run the app using: uvicorn jwks_server:app --reload
