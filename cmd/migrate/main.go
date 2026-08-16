// Command migrate applies PostgreSQL schema migrations (embed in the
// binary; idempotent via goose version tracking).
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"selfu/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate up|down|status")
		os.Exit(2)
	}
	cmd := os.Args[1]

	dbURL := os.Getenv("SELFU_DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "SELFU_DATABASE_URL is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	msg, err := store.RunMigration(ctx, dbURL, cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
	fmt.Println(msg)
}
