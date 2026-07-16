# Dark-Recon Makefile — common dev/install entry points.
BINARY   := dark-recon
CMD      := ./cmd/dark-recon
LDFLAGS  := -s -w
PORT     := 5000

.DEFAULT_GOAL := build
.PHONY: build run mcp vet test fmt check-prereqs install-tools deb clean help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the static, self-contained binary (CGO disabled)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(CMD)

run: build ## Build and run the web server
	./$(BINARY) -port $(PORT)

mcp: build ## Run the MCP server (stdio) against a local Dark-Recon instance
	./$(BINARY) mcp

vet: ## Run go vet
	go vet ./...

test: vet ## Run go vet + tests
	go test ./...

fmt: ## Format Go code
	go fmt ./...

check-prereqs: ## Check that required security tools & dependencies are installed
	@bash scripts/check-prereqs.sh

install-tools: ## Install the Go/apt/pip security tools Dark-Recon drives
	@bash scripts/install-tools.sh

deb: ## Build the .deb package (Linux)
	@bash dist/build-deb.sh

clean: ## Remove build artifacts
	rm -f $(BINARY)
	rm -rf dist/staging dist/*.deb
