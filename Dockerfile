# syntax=docker/dockerfile:1
# Multi-stage build: static Go binaries into a minimal runtime.
FROM golang:1.26.6 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authentik-bootstrap ./cmd/authentik-bootstrap \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY --from=build /out/authentik-bootstrap /usr/local/bin/authentik-bootstrap
COPY --from=build /out/worker /usr/local/bin/worker
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/api"]