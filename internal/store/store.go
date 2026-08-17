// Package store implements PostgreSQL persistence for the platform.
// PostgreSQL is the platform's source of truth (spec §21); every external
// system (authentik, chasquid, Traefik, Docker) holds observed state only.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps the PostgreSQL connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL, retrying briefly to tolerate compose
// container startup ordering, and verifies connectivity with a ping.
func Open(ctx context.Context, dbURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	var lastErr error
	for range 10 {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			return &Store{pool: pool}, nil
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("database connect: %w", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("database not reachable after retries: %w", lastErr)
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when an insert would violate a uniqueness
// constraint (e.g. duplicate slug or email).
var ErrConflict = errors.New("store: conflict")

// isUnique reports whether err is a PostgreSQL unique-violation (23505),
// including when wrapped.
func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
