.PHONY: build run tidy test docker compose-up compose-down

BINARY := vara-backend
PKG    := ./cmd/server

build:
	go build -o bin/$(BINARY) $(PKG)

run:
	go run $(PKG)

tidy:
	go mod tidy

test:
	go test ./...

docker:
	docker build -f deployments/docker/Dockerfile -t $(BINARY):dev .

compose-up:
	docker-compose up --build

compose-down:
	docker-compose down
