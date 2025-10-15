FROM python:3.11-slim

WORKDIR /app

# system deps for magic and clamav client
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV FLASK_APP=app
ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "serve.py"]
