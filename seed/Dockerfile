FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/seed ./seed

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/seed /app/seed
COPY --from=builder /src/seed/isms_p_controls.json /app/isms_p_controls.json
ENV ISMS_CONTROLS_FILE=/app/isms_p_controls.json
USER nonroot:nonroot
ENTRYPOINT ["/app/seed"]
