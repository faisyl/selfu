# syntax=docker/dockerfile:1
# Minimal chasquid MTA image: chasquid 1.17.0 built from the pinned source
# tag (spec §89) + the selfu chasquid-agent sidecar (spec §59). The platform
# owns /etc/chasquid as generated state (spec §60); no latest tags (§89).

FROM golang:1.26.6 AS chasquid-build
WORKDIR /src
RUN git clone --depth 1 --branch v1.17.0 https://gitlab.com/albertito/chasquid.git . \
 && CGO_ENABLED=0 go install ./...

FROM golang:1.26.6 AS agent-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/chasquid-agent ./cmd/chasquid-agent

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata openssl
COPY --from=chasquid-build /go/bin/chasquid /usr/local/bin/chasquid
COPY --from=chasquid-build /go/bin/chasquid-util /usr/local/bin/chasquid-util
COPY --from=chasquid-build /go/bin/smtp-check /usr/local/bin/smtp-check
COPY --from=agent-build /out/chasquid-agent /usr/local/bin/chasquid-agent
COPY docker/chasquid/mda.sh /usr/local/bin/mda.sh
COPY docker/chasquid/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/mda.sh /entrypoint.sh
EXPOSE 25 587 8530
ENTRYPOINT ["/entrypoint.sh"]