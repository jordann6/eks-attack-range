# Pinned to an OLD base on purpose. Debian bullseye slim from the 3.11 line
# carries known OS-package CVEs, so ECR scan-on-push lights up and gives the
# "the scanner already knew before the attacker did" beat in the write-up. This
# is the SearchSploit / Exploit-DB analogue. The blue-team image moves to a
# current slim base and a rebuilt dependency set.
FROM python:3.11-slim-bullseye

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Runs as root (no USER directive) on purpose: PodSecurity is off in the lab, so
# the foothold lands as root in the container. The hardened overlay runs as a
# non-root user under the restricted PodSecurity standard.
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
