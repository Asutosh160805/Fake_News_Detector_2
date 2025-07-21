import os
import sqlite3
import hashlib
from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import InferenceClient
from dotenv import load_dotenv  # for loading .env file

# Load API key
load_dotenv()
HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    raise RuntimeError("HF_TOKEN missing in environment or .env file")

# Init FastAPI
app = FastAPI()

# Allow CORS for all
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to SQLite DB
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT
)
''')
conn.commit()

# Hashing passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Signup route
@app.post("/signup")
async def signup(name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    try:
        cursor.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                       (name, email, hash_password(password)))
        conn.commit()
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")

# Login route
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    hashed = hash_password(password)
    cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, hashed))
    user = cursor.fetchone()
    if user:
        return {"success": True}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Pydantic model for incoming prediction request
class PredictRequest(BaseModel):
    message: str

# Setup Hugging Face Inference Client for Mixtral
client = InferenceClient(
    provider="together",
    api_key=HF_TOKEN,
)

# Prediction route using Mixtral
@app.post("/predict")
@app.post("/predict")
async def predict(request: PredictRequest):
    try:
        # System prompt to guide the model
        result = client.chat.completions.create(
            model="mistralai/Mixtral-8x7B-Instruct-v0.1",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a fake news detection model. "
                        "Your job is to classify if a news headline or article is FAKE or REAL. "
                        "Respond with either 'FAKE' or 'REAL' followed by a short one-line reason. "
                        "Don't act like a chatbot. Don't reply with anything else."
                    )
                },
                {
                    "role": "user",
                    "content": request.message
                }
            ]
        )
        response = result.choices[0].message.content.strip()
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")