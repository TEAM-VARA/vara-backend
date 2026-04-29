# VARA compliance API 서버 (main.go).
# Multi-stage 로 alpine builder 에서 정적 바이너리를 만들고 distroless 위에 올린다.

FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/vara-api .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/vara-api /app/vara-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/vara-api"]
