# Hardened image: current slim base and a rebuilt dependency set, the opposite
# of the baseline's deliberately-old bullseye + old anthropic SDK. ECR scan-on-
# push should come back clean here, which is the "the fix also closed the known
# CVEs" beat in the write-up.
FROM python:3.12-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Non-root by default. The pod also runs under the restricted PodSecurity
# standard with a locked securityContext from the defend/hardened overlay; this
# USER line means the image is non-root even if run outside that overlay.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
