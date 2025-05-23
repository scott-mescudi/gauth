# Variables
PKG := ./...

.PHONY: all fmt test lint build clean help

# Default target
all: fmt lint test build ## Format, lint, test, and build the project

# Format Go code
fmt: ## Format the code
	@echo "Formatting Go code..."
	@go fmt $(PKG)

# Test the code
test: ## Run tests
	@echo "Running tests..."
	@go test  $(PKG)

# Lint the code
lint: ## Lint the code using go vet
	@echo "Linting code..."
	@go vet $(PKG)

cov:
	@echo "Getting test coverage"
	@go test -cover ./...

coverage:
	@echo "Getting test coverage"
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html


# Clean the build cache
clean: ## Clean build cache
	@echo "Cleaning up..."
	@go clean

# Help menu
help: ## Display this help
	@echo "Usage: make [target]"
	@echo
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'