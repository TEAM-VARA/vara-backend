# BGE-M3 임베딩 서버 (FastAPI + sentence-transformers).
# CPU 전용 torch 휠을 사용해 이미지 크기를 줄였다 (~1.5GB → GPU 빌드는 3GB+).
# 모델 가중치(약 2.3GB)는 컨테이너 시작 시 HF Hub 에서 다운로드되며,
# K8s 매니페스트에서 emptyDir 또는 PVC 를 /cache/hf 에 마운트해 재시작 시 재다운로드를 피한다.

FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

# embedding_server.py 는 VARA/ 루트에 있으므로 build context 를 VARA/ 로 잡고 복사한다.
# (docker build 시 -f VARA/embedding-server/Dockerfile VARA/ 형태로 호출)
COPY embedding_server.py /app/embedding_server.py

ENV HF_HOME=/cache/hf
ENV TRANSFORMERS_CACHE=/cache/hf
ENV TOKENIZERS_PARALLELISM=false

EXPOSE 9000

CMD ["uvicorn", "embedding_server:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1"]
