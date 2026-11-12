FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home decoy && mkdir /data /app && chown decoy /data \
 && (command -v openssl >/dev/null || (apt-get update -q && apt-get install -y -q --no-install-recommends openssl \
     && rm -rf /var/lib/apt/lists/*)) \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=kube-apiserver" \
      -addext "subjectAltName=DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,DNS:kubernetes.default.svc.cluster.local,DNS:fileserver01,IP:10.96.0.1,IP:10.0.0.15" \
      -keyout /app/k8s.key -out /app/k8s.crt 2>/dev/null \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=fileserver01.northbridge.local" \
      -keyout /app/rdp.key -out /app/rdp.crt 2>/dev/null \
 && chown decoy /app/*.key && chmod 400 /app/*.key
COPY honeysvc.py /app/honeysvc.py
USER decoy
CMD ["python", "-I", "-u", "/app/honeysvc.py"]
