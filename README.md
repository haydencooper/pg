# pg

a postgres client in go with no dependencies: the simple and extended query protocols with text values, md5 and scram-sha-256, listen and notify, and transactions that say when a commit's outcome is unknown.

it began as iris's own client, and lives here so every service can share it.

## tests

    go test ./...

`scripts/pg-test.sh` runs the integration tests against a throwaway cluster (`PG_BIN` names postgres's bin directory when it isn't on PATH).
