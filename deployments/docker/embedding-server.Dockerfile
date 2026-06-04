# BGE-M3 FastAPI 임베딩 서버 (CPU 휠).
# build context: vara-backend/ (project root)
#   docker build -f deployments/docker/embedding-server.Dockerfile -t vara-embedding:dev .

FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY embedding-server/requirements.txt .
RUN pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

COPY embedding-server/embedding_server.py /app/embedding_server.py

ENV HF_HOME=/cache/hf
ENV TRANSFORMERS_CACHE=/cache/hf
ENV TOKENIZERS_PARALLELISM=false

EXPOSE 9000
CMD ["uvicorn", "embedding_server:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1"]
