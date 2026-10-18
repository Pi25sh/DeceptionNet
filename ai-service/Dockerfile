FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# anthropic 0.19.x predates httpx>=0.28 (which removed the `proxies` kwarg the
# SDK passes to httpx.Client). Keep this in its OWN layer so it never invalidates
# the big torch/sentence-transformers install above on rebuilds.
RUN pip install --no-cache-dir "httpx==0.27.2"

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
