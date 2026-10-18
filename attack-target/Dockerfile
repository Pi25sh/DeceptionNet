FROM python:3.10-slim

WORKDIR /app

# The vulnerable web app.
COPY app.py .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Where interaction logs land; the forwarder tails this volume.
ENV TARGET_LOG_FILE=/var/log/attack-target/target.jsonl \
    SHIP_EVENTS=false \
    TARGET_PORT=9090

# Uvicorn-style host/port; Flask is dev-served here because this is a lab.
EXPOSE 9090

CMD ["python", "app.py"]
