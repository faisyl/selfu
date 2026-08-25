# selfu — Phase 1 development targets.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet fmt up down psql gen-env migrate-up migrate-status doctor bootstrap clean

build:
	go build -ldflags "-X selfu/internal/version.Version=$(VERSION)" ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Regenerate secrets in .env (keeps non-secret fields).
gen-env:
	@test -f .env || cp .env.example .env
	@sed -i.bak \
		-e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$$(openssl rand -hex 24)|" \
		-e "s|^AUTHENTIK_SECRET_KEY=.*|AUTHENTIK_SECRET_KEY=$$(openssl rand -hex 32)|" \
		-e "s|^AUTHENTIK_BOOTSTRAP_PASSWORD=.*|AUTHENTIK_BOOTSTRAP_PASSWORD=$$(openssl rand -hex 16)|" \
		-e "s|^AUTHENTIK_BOOTSTRAP_TOKEN=.*|AUTHENTIK_BOOTSTRAP_TOKEN=$$(openssl rand -hex 32)|" \
		-e "s|^SELFU_SESSION_SECRET=.*|SELFU_SESSION_SECRET=$$(openssl rand -hex 32)|" \
		-e "s|^SELFU_OIDC_CLIENT_SECRET=.*|SELFU_OIDC_CLIENT_SECRET=$$(openssl rand -hex 32)|" \
		.env && rm -f .env.bak
	@grep -E '(PASSWORD|SECRET|TOKEN)=' .env | sed 's/=.*/=<random>/' 

up:
	docker compose up -d --wait

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs -f

migrate-up:
	go run ./cmd/migrate up

migrate-status:
	go run ./cmd/migrate status

# Preflight checks for a selfu host (docker, ports, .env, DNS, Cloudflare).
doctor:
	go run ./cmd/doctor

# One-command first-run setup: doctor -> env -> stack -> migrations ->
# OIDC bootstrap -> catalog seed. Idempotent; safe to re-run.
bootstrap:
	./scripts/bootstrap.sh

clean:
	docker compose down -v
	go clean ./...