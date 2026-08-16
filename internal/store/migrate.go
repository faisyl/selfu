package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration commands accepted by the migrate CLI.
const (
	CmdUp     = "up"
	CmdDown   = "down"
	CmdStatus = "status"
)

// RunMigration applies pg-backed schema migrations.
func RunMigration(ctx context.Context, dbURL, cmd string) (string, error) {
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return "", fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return "", fmt.Errorf("set dialect: %w", err)
	}

	switch cmd {
	case CmdUp:
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			return "", fmt.Errorf("migrate up: %w", err)
		}
	case CmdDown:
		if err := goose.DownContext(ctx, db, "migrations"); err != nil {
			return "", fmt.Errorf("migrate down: %w", err)
		}
	case CmdStatus:
		if err := goose.StatusContext(ctx, db, "migrations"); err != nil {
			return "", fmt.Errorf("migrate status: %w", err)
		}
	default:
		return "", fmt.Errorf("unknown migration command %q (want up|down|status)", cmd)
	}

	v, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return "", fmt.Errorf("get version: %w", err)
	}
	return fmt.Sprintf("schema version: %d", v), nil
}
