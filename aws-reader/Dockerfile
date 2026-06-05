FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /out/aws-reader .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/aws-reader /aws-reader
ENTRYPOINT ["/aws-reader"]