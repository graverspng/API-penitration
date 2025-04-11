from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt
import sqlite3
import logging
import os
import random
from datetime import datetime, timedelta
from typing import Optional


SECRET_KEY = os.urandom(32)
ALGORITHM = "HS256"
app = FastAPI()


logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        mfa_code TEXT,
        failed_attempts INTEGER DEFAULT 0
    )
""")
conn.commit()


test_users = [
    ("admin", "admin123", "admin", None),
    ("user1", "password1", "user", None),
    ("guest", "guest123", "guest", None)
]
cursor.executemany("INSERT INTO users (username, password, role, mfa_code) VALUES (?, ?, ?, ?)", test_users)
conn.commit()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
failed_logins = {} 

def generate_mfa_code():
    return str(random.randint(100000, 999999))

def log_attack(ip: str, attack_type: str, details: str):
    logging.warning(f"ATTACK DETECTED - IP: {ip} - Type: {attack_type} - Details: {details}")


async def waf_check(request: Request):
    ip = request.client.host
    suspicious_keywords = ["' OR", "SELECT", "UNION", "DROP", "<script>", "../"]
    
    for keyword in suspicious_keywords:
        if keyword in str(request.url) or keyword in str(await request.body()):
            log_attack(ip, "WAF_BLOCK", f"Suspicious keyword: {keyword}")
            raise HTTPException(status_code=403, detail="Request blocked by WAF")




@app.post("/token")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    request: Request = None
):
    ip = request.client.host

    await waf_check(request)
    

    if failed_logins.get(ip, 0) >= 5:
        log_attack(ip, "BRUTE_FORCE", "Too many failed login attempts")
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    
    if not user or user[2] != password:
        failed_logins[ip] = failed_logins.get(ip, 0) + 1
        log_attack(ip, "FAILED_LOGIN", f"Username: {username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    

    mfa_code = generate_mfa_code()
    cursor.execute("UPDATE users SET mfa_code=? WHERE username=?", (mfa_code, username))
    conn.commit()
    
    logging.info(f"MFA code generated for {username}: {mfa_code}")
    return {"message": "Enter MFA code", "mfa_code": mfa_code}


@app.post("/mfa")
async def verify_mfa(
    username: str = Form(...),
    mfa_code: str = Form(...),
    request: Request = None
):
    ip = request.client.host
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    
    if not user or user[4] != mfa_code:
        log_attack(ip, "MFA_BRUTE_FORCE", f"User: {username}")
        raise HTTPException(status_code=401, detail="Invalid MFA code")


    token_data = {
        "sub": username,
        "role": user[3],
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    logging.info(f"Successful login: {username}")
    return {"access_token": token, "token_type": "bearer"}


@app.get("/secure-data")
async def get_secure_data(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload["role"] not in ["admin", "user"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return {"message": "Secure data accessed successfully!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/admin-backdoor")
async def honeypot(request: Request):
    ip = request.client.host
    log_attack(ip, "HONEYPOT_TRIGGERED", "Attempted access to fake admin endpoint")
    return {"message": "Nothing to see here..."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)