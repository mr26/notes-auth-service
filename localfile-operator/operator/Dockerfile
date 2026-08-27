FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY handlers.py .

# --standalone skips kopf's peering CRD (not needed for a single replica)
ENTRYPOINT ["kopf", "run", "--standalone", "--all-namespaces", "/app/handlers.py"]
