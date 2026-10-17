VERSION ?= dev
BIN     := bin/gotalk-gateway
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build run test test-unit lint fmt sqlc sqlc-check openapi docker up down logs smoke tidy clean help

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gotalk-gateway

run: ## Run the gateway locally with config.example.yaml (needs PostgreSQL; see `make up`)
	go run ./cmd/gotalk-gateway serve --config config.example.yaml --log-format text

test: ## Run all tests, including PostgreSQL tests in containers (needs Docker)
	go test -race -coverprofile=coverage.out ./...

test-unit: ## Run tests without PostgreSQL containers
	go test -short ./...

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code
	golangci-lint fmt

sqlc: ## Regenerate internal/store from the queries and migrations
	sqlc generate

sqlc-check: ## Fail if internal/store is out of date
	sqlc diff

openapi: ## Print the OpenAPI spec of the implemented endpoints
	@go run ./cmd/gotalk-gateway openapi

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t ghcr.io/parkerbrown98/gotalk-gateway:$(VERSION) .

up: ## Start the gateway, PostgreSQL and Redis with Docker Compose
	docker compose up -d --build --wait

down: ## Stop the Compose stack
	docker compose down

logs: ## Follow the gateway logs
	docker compose logs -f gateway

smoke: ## Check a running gateway (default http://localhost:8090)
	./scripts/smoke.sh $(or $(URL),http://localhost:8090)

tidy: ## Tidy go.mod
	go mod tidy

clean: ## Remove build output
	rm -rf bin dist coverage.out
