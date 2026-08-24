# SVALINN-GO Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM golang:1.26.5-alpine AS builder

# Install build dependencies (CGO needed for SQLite)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with CGO enabled for SQLite
ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o svalinn ./cmd/svalinn

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /app/svalinn .

# Copy config
COPY configs/ ./configs/

# Expose ports
EXPOSE 10000
EXPOSE 10443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:10000/health || exit 1

# Run as non-root; create the data dir after adduser so it's owned by the
# user that will actually write to it (gray-zone state, countermeasures
# action log, attacker-memory) instead of staying root-owned and unwritable.
RUN adduser -D -u 1000 svalinn
RUN mkdir -p /app/data && chown -R svalinn:svalinn /app/data
USER svalinn

# Start
ENTRYPOINT ["./svalinn"]
CMD ["-config", "configs/svalinn.yaml"]
