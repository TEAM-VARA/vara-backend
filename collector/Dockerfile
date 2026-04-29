# Trivy 바이너리를 collector 이미지에 함께 포함시켜야 image scanning 이 동작한다.
# multi-stage 로 (1) collector Go binary 빌드 → (2) trivy 베이스 이미지 위에 collector 만 얹는다.

FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/collector ./collector

# aquasec/trivy 이미지에는 trivy 바이너리와 vuln DB 캐시 디렉토리가 미리 준비되어 있다.
FROM aquasec/trivy:0.58.0
WORKDIR /app
COPY --from=builder /out/collector /app/collector

# Trivy DB 를 매번 다운로드하지 않도록 PVC/EmptyDir 마운트를 권장.
ENV TRIVY_CACHE_DIR=/tmp/trivy-cache
ENV TRIVY_BIN=/usr/local/bin/trivy

ENTRYPOINT ["/app/collector"]
