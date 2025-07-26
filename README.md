# 🧠 Fake News Detector

An intelligent multi-source **Retrieval-Augmented Generation (RAG)** powered fake news detection system.

---

## 📌 Table of Contents

- [About the Project](#about-the-project)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Virtual Environment Setup](#virtual-environment-setup)
  - [Installation](#installation)
  - [Setting Environment Variables](#setting-environment-variables)
- [Usage](#usage)
- [Architecture & Flow](#architecture--flow)
- [API Keys and Tokens](#api-keys-and-tokens)
- [Project Members](#project-members)
- [Further Improvements](#further-improvements)
- [License](#license)

---

## 📖 About the Project

This project is a **Fake News Detector** that classifies news articles or headlines as **FAKE**, **REAL**, or **UNCERTAIN** by combining large language model reasoning with real-time evidence retrieval from **Wikipedia**, **GNews**, and **trusted fact-checkers**.

Built using an **agentic RAG approach**, it ensures explainable, up-to-date, and reliable detection.

---

## ✨ Features

- 🔎 Multi-source evidence retrieval (Wikipedia + GNews + extended sources)
- 🧠 Robust claim extraction and aggregation
- 🤖 LLM inference with Hugging Face's [Mixtral-8x7B-Instruct](https://huggingface.co/mistralai/Mixtral-8x7B-Instruct-v0.1)
- 🔐 Secure user authentication (signup/login)
- 💻 Modern frontend UI with animated background
- 🧩 Modular and scalable backend (FastAPI-based)

---

## 🚀 Getting Started

### ✅ Prerequisites

- Python `3.8` or higher
- (Optional) Node.js and npm (for frontend customization/build)
- Internet connection (for API calls)
- API keys from:
  - [GNews](https://gnews.io/)
  - [Hugging Face](https://huggingface.co/)
  - [NewsAPI (Optional)](https://newsapi.org/)

---

### 📦 Virtual Environment Setup

```bash
# Navigate to your project directory
cd /path/to/your/project

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate

# Windows
py -m venv .venv
.venv\Scripts\activate
```

🔐 Setting Environment Variables
Create a .env file in your project root and add:
```.env
HF_TOKEN=your_huggingface_together_api_key
GNEWS_API_KEY=your_gnews_api_key
NEWS_API_KEY=your_newsapi_org_key   # Optional
```

🧬 Architecture & Flow
=>Backend Flow:

=>User submits text via /predict

=>Extract main claim

=>Retrieve real-time evidence from:

=>Wikipedia

=>GNews

=>NewsAPI (optional)

=>Compose chain-of-thought agentic prompt

=>Query Mixtral LLM for classification

=>Return verdict: ✅ REAL | ❌ FAKE | ❓ UNCERTAIN

=>Frontend displays result + explanation

🔑 API Keys and Tokens
🔹 GNews API
📎 https://gnews.io/

🔹 Hugging Face Inference API
📎 https://huggingface.co/

Use model: mistralai/Mixtral-8x7B-Instruct-v0.1

🔹 NewsAPI (Optional)
📎 https://newsapi.org/

👥 Project Members
| Name              | Role                                      |
| ----------------- | ----------------------------------------- |
| Deepam Pattnaik   | Backend Developer                         |
| Asutosh Dash      | Frontend Developer                        |
| Arun Kumar Biswal | Database, API Integration & Documentation |

🔧 Further Improvements
🔍 Advanced NLP claim extraction (e.g., Named Entity Recognition)

✅ More fact-checker sources: Snopes, PolitiFact, etc.

⚡ Vector search + caching for faster performance

🖼️ Support for multimodal inputs (images/videos)

🌈 UI/UX enhancements: dark/light toggle, real-time feedback

📚 Requirements
fastapi==0.95.2
uvicorn==0.22.0
requests==2.31.0
python-dotenv==1.0.0
huggingface_hub==0.14.1
sqlite3 is built into Python and requires no separate installation.






