from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import hashlib
from transformers import pipeline

app = FastAPI()

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB setup
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

# Request body for prediction
class PredictRequest(BaseModel):
    message: str

# Load lightweight text generation model (GPT-2)
chatbot = pipeline("text-generation", model="gpt2")

@app.post("/predict")
async def predict(request: PredictRequest):
    prompt = request.message

    try:
        # Generate text with limited length
        result = chatbot(prompt, max_new_tokens=100, num_return_sequences=1)
        response = result[0]["generated_text"]
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")
