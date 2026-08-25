// Command seed idempotently converges the built-in application catalog
// (internal/catalog.BuiltIns) into the database. It runs as a compose one-shot
// service during bootstrap so first-run and acceptance never need a manual
// "seed it first". Safe to re-run: entries are upserted on (slug, version).
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"selfu/internal/catalog"
	"selfu/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	dbURL := os.Getenv("SELFU_DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("SELFU_DATABASE_URL is required")
	}
	s, err := store.Open(ctx, dbURL)
	if err != nil {
		return err
	}
	defer s.Close()

	for _, m := range catalog.BuiltIns() {
		if err := s.UpsertCatalogApp(ctx, m); err != nil {
			return err
		}
		fmt.Printf("seed: catalog entry %s %s (slug %q) ensured\n",
			m.ID, m.Version, m.ID)
	}
	fmt.Println("seed: catalog ready")
	return nil
}
