import os
import sqlite3
import hashlib
import requests
from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import InferenceClient
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()
HF_TOKEN = os.getenv("HF_TOKEN")
NEWS_API_KEY = os.getenv("NEWS_API_KEY")  # NewsAPI.org key
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")  # GNews API key

if not HF_TOKEN:
    raise RuntimeError("HF_TOKEN missing in environment or .env file")
if not NEWS_API_KEY:
    raise RuntimeError("NEWS_API_KEY missing in environment or .env file")
if not GNEWS_API_KEY:
    raise RuntimeError("GNEWS_API_KEY missing in environment or .env file")

# --- Setup FastAPI app ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# --- Setup SQLite ---
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
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, hash_password(password)),
        )
        conn.commit()
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    hashed = hash_password(password)
    cursor.execute(
        "SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, hashed)
    )
    user = cursor.fetchone()
    if user:
        return {"success": True}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# --- Request model ---
class PredictRequest(BaseModel):
    message: str

# --- Evidence retrieval helpers ---

def extract_main_claim(text: str) -> str:
    """
    Very simple extraction by taking first ~8 words.
    Improve by using NLP/NER for production.
    """
    words = text.split()
    claim = " ".join(words[:8]) if len(words) >= 3 else text
    return claim.strip(" .,")

def fetch_wikipedia_summary(query: str) -> str:
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{query.replace(' ', '_')}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("extract", "")
    except Exception:
        pass
    return ""

def fetch_newsapi_headlines(query: str) -> str:
    url = f"https://newsapi.org/v2/everything?q={query}&language=en&pageSize=3&apiKey={NEWS_API_KEY}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "articles" in data and data["articles"]:
                snippets = []
                for article in data["articles"]:
                    title = article.get("title", "")
                    desc = article.get("description", "")
                    snippets.append(f"{title}: {desc}")
                return "\n".join(snippets)
    except Exception:
        pass
    return ""

def fetch_gnews_headlines(query: str) -> str:
    """
    Fetch top 3 news headlines + descriptions from GNews API
    Docs: https://gnews.io/docs/
    """
    url = f"https://gnews.io/api/v4/search?q={query}&lang=en&max=3&token={GNEWS_API_KEY}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            articles = data.get("articles", [])
            snippets = []
            for art in articles:
                title = art.get("title", "")
                desc = art.get("description", "")
                snippets.append(f"{title}: {desc}")
            return "\n".join(snippets)
    except Exception:
        pass
    return ""

def fetch_factchecker_rss(query: str) -> str:
    """
    Placeholder: Implement scraping or RSS fetch of Snopes/PolitiFact or other fact-checkers.
    Returning empty string for now.
    """
    return ""

# --- Initialize HuggingFace Inference Client ---
client = InferenceClient(
    provider="together",
    api_key=HF_TOKEN,
)

# --- Predict route ---
@app.post("/predict")
async def predict(request: PredictRequest):
    try:
        claim = extract_main_claim(request.message)

        # Retrieve multi-source evidence
        wiki_summary = fetch_wikipedia_summary(claim)
        newsapi_snippets = fetch_newsapi_headlines(claim)
        gnews_snippets = fetch_gnews_headlines(claim)
        factchecker_snippets = fetch_factchecker_rss(claim)

        # Aggregate all evidence snippets
        all_evidence_parts = [wiki_summary, newsapi_snippets, gnews_snippets, factchecker_snippets]
        all_evidence = "\n".join(part for part in all_evidence_parts if part).strip()

        if not all_evidence:
            all_evidence = "No relevant evidence found in Wikipedia, news, or fact-checking sources."

        # Compose agentic system prompt
        system_prompt = (
            "You are a professional fake news detection assistant. "
            "Analyze the user's statement and evidence from MULTIPLE sources below. "
            "Base your conclusion on both external evidence and your internal knowledge.\n"
            "Reply in steps:\n"
            "Step 1: Restate the main claim.\n"
            "Step 2: Compare it with evidence from Wikipedia and news sources.\n"
            "Step 3: Classify as FAKE, REAL, or UNCERTAIN, and provide a one-line, evidence-based reason.\n"
            "If evidence is insufficient or ambiguous, reply UNCERTAIN.\n"
            f"User's message: {request.message}\n"
            f"Multi-source evidence: {all_evidence}"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": request.message},
        ]

        # Call LLM to get response
        result = client.chat.completions.create(
            model="mistralai/Mixtral-8x7B-Instruct-v0.1",
            messages=messages,
        )
        response = result.choices[0].message.content.strip()

        # Validate response for classification label
        if not any(label in response for label in ["FAKE", "REAL", "UNCERTAIN"]):
            response = (
                "UNCERTAIN: Model could not confidently classify based on current evidence. "
                "Please try a different claim."
            )

        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")
