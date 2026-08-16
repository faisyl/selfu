#!/bin/sh
# Creates the two platform databases (selfu for the platform, authentik
# for the identity provider) on the shared PostgreSQL instance.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE DATABASE authentik OWNER $POSTGRES_USER;
EOSQL