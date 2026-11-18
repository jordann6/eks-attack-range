# In-cluster responder. Stdlib for the Kubernetes API, boto3 for S3 via IRSA.
# Non-root, read-only root filesystem (set in the Deployment), no shell needed.
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY responder.py .
USER 10001
CMD ["python3", "-u", "responder.py"]
