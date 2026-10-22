# pg

a postgres client in go with no dependencies. it speaks the simple and extended query protocols with text values, md5 and scram-sha-256, listen and notify, transactions that say when a commit's outcome is unknown, and batches that cost one round trip.

it began as iris's own client, and lives here so every service shares one.

## connecting

    cfg, err := pg.ParseURL("postgres://user:password@db.example:5432/app?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem")
    conn, err := pg.Connect(ctx, cfg)

the url may set `host` (a unix socket's directory), `application_name`, `sslmode` and `sslrootcert`, and nothing else. a key set twice is refused, and so is `sslrootcert` with `sslmode=disable`. an error never repeats any part of the url.

## tls

- over tcp, tls is on unless `sslmode=disable`. it is `verify-full`: the chain is checked against `sslrootcert` (or the system's authorities), and the host dialed must be named in the certificate.
- the minimum is tls 1.2, and the client offers alpn `postgresql`.
- the server's answer to the tls request is read straight off the socket, so nothing it sends before the handshake is read as postgres.
- a config's tls mode is `off`, `verify-full`, or unset, which means the default. an unknown mode is refused before dialing.
- tls over a unix socket isn't spoken. a socket's session is in the clear.

## logging in

- over tls, only scram-sha-256-plus bound to the server's certificate (tls-server-end-point) is accepted. md5, trust, unbound scram and cleartext are all refused, so a tls session can't be talked down.
- a certificate signed with ed25519 can't be bound, so it is refused.
- in the clear: trust, md5 or scram-sha-256. cleartext is always refused.

## batches

    res, err := conn.Batch(ctx,
        pg.Statement{SQL: "SELECT set_config('app.tenant', $1, true)", Args: []any{tenant}},
        pg.Statement{SQL: "SELECT name FROM platform.tenant_modules"},
    )

a batch goes out in one write and comes back in one round trip. outside a transaction postgres runs it as one of its own: every statement applies or none does, and `set_config(..., true)` lasts until the batch ends, as long as no statement in it begins, commits or rolls back a transaction. a batch that leaves a transaction open is rolled back and is an error, so a tenant set in it can't leak into the session's next use. the first statement to fail is a `*pg.BatchError` naming it; a failure when the batch commits is blamed on its last statement. every row is read into memory, so batches are for bounded results.

`Err` says why a session can't be used any more (it was closed, cut by a cancelled context, or broken by the server), and is nil while it can; a pool drops a session once it has one.

## tests

    go test ./...

`scripts/pg-test.sh` runs the integration tests against a throwaway cluster with tls on, using a throwaway authority from `internal/testcerts` (`PG_BIN` names postgres's bin directory when it isn't on PATH). ci runs format, vet, the tests, four fuzzers (the server's answers to a query, the tls answer, the scram messages and a batch's answers), and the integration tests on postgres 16 with tls on.
