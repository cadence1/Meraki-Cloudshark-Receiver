FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Captures persist via a mounted volume (see docker-compose.yml)
ENV CLOUDSHARK_CAPTURES_DIR=/data/captures
ENV CLOUDSHARK_RECEIVER_BIND_HOST=0.0.0.0
RUN mkdir -p /data/captures

EXPOSE 8642
CMD ["python", "server.py"]
