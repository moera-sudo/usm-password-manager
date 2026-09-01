SHELL := /bin/bash
GO ?= go

BIN_DIR := bin
CLIENT := $(BIN_DIR)/usm
SERVER := $(BIN_DIR)/usmd

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)

GOLANGCI_VERSION ?= v2.13.2
GOLANGCI := $(BIN_DIR)/golangci-lint

.DEFAULT_GOAL := help

.PHONY: help build build-client build-server run fmt fmt-check tidy vet test test-vectors cover clean

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build        - Build the client and server binaries"
	@echo "  build-client - Build the only ./$(CLIENT)"
	@echo "  build-server - Build the only ./$(SERVER)"
	@echo "  run          - Run the client from source"
	@echo "  fmt          - Run gofmt on the code"
	@echo "  fmt-check    - Run gofmt on the code and check for errors"
	@echo "  tidy         - Run go mod tidy"
	@echo "  vet          - Run go vet"
	@echo "  test         - Run all tests with the race detector"
	@echo "  test-vectors - Run only RFC test-vector checks"
	@echo "  cover        - Produce coverage.out and print a summary"
	@echo "  clean        - Remove build artifacts"
	@echo "  tools        - Install golangci-lint into ./$(BIN_DIR)"
	@echo "  lint         - Run golangci-lint"
	@echo "  lint-fix     - Run golangci-lint with autofixes"
	@echo "  ci           - Everything CI runs: fmt-check, vet, lint, test"

	
build: build-client build-server

build-client:
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(CLIENT) ./cmd/usm

build-server:
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(SERVER) ./cmd/usmd

run: 
	$(GO) run ./cmd/usm

fmt:
	gofmt -s -w .

fmt-check:
	@files=$$(gofmt -s -l .); \
	if [ -n "$$files" ]; then \
		echo "these files are not formatted:"; \
		echo "$$files"; \
		exit 1; \
	fi

tidy:
	$(GO) mod tidy

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

test-vectors:
	$(GO) test -race -run 'Vector' ./...

cover:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

tools:
	@mkdir -p $(BIN_DIR)
	GOBIN=$(CURDIR)/$(BIN_DIR) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	@$(GOLANGCI) version

lint:
	$(GOLANGCI) run ./...

lint-fix:
	$(GOLANGCI) run --fix ./...

ci: fmt-check vet lint test
