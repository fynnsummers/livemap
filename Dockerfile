FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends whois ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py dbutil.py f2b-host.sh /app/
COPY static /app/static
COPY data /app/data
RUN chmod +x /app/f2b-host.sh

ENV LIVEMAP_HOST=0.0.0.0 \
    LIVEMAP_PORT=8791 \
    LIVEMAP_F2B_SUDO=0 \
    LIVEMAP_F2B_BIN=/app/f2b-host.sh \
    PYTHONUNBUFFERED=1

EXPOSE 8791
CMD ["python3", "/app/server.py"]
