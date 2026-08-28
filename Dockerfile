# ============================================================
#  NetGuard AI — FastAPI Backend Dockerfile
#  Target: Hugging Face Spaces (Docker SDK) / any Docker host
# ============================================================
#  Uses the primary FastAPI app at frontend/app.py
#  Models + RAG knowledge base are loaded at startup.
# ============================================================

FROM python:3.12-slim

# Avoid interactive prompts & bytecode caches
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/code

WORKDIR /code

# 1) Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) Copy the full application
COPY . .

# Hugging Face Spaces serves on port 7860 by default
EXPOSE 7860

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:7860/health', timeout=5)" || exit 1

# Run the FastAPI backend
CMD ["uvicorn", "frontend.app:app", "--host", "0.0.0.0", "--port", "7860"]
