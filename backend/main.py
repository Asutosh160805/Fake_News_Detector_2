from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import hashlib

app = FastAPI()

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create users table if not exists
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT
)
''')
conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.post("/signup")
async def signup(name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    try:
        cursor.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                       (name, email, hash_password(password)))
        conn.commit()
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    hashed = hash_password(password)
    cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, hashed))
    user = cursor.fetchone()
    if user:
        return {"success": True}
    raise HTTPException(status_code=401, detail="Invalid credentials")
