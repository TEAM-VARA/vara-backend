FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vara-backend ./cmd/server

FROM alpine:3.20

# 런타임 의존성 + trivy + tesseract-ocr + pdftotext 설치
RUN apk add --no-cache ca-certificates curl \
        tesseract-ocr \
        tesseract-ocr-data-eng \
        tesseract-ocr-data-kor \
        poppler-utils \
        poppler-data && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin v0.70.0 && \
    apk del curl && \
    mkdir -p /var/cache/trivy

COPY --from=builder /out/vara-backend /app/vara-backend
COPY --from=builder /src/rulesets /app/rulesets
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/vara-backend"]
