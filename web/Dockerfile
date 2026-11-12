FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "aiohttp>=3.11,<4" \
    && useradd -r -u 10001 -m hp && mkdir /data && chown hp /data

COPY app.py entrypoint.sh warm_paths.txt /app/
RUN chmod +x /app/entrypoint.sh

USER hp
WORKDIR /app
EXPOSE 8080 8443
ENTRYPOINT ["/app/entrypoint.sh"]
