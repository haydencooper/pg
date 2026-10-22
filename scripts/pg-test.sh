#!/usr/bin/env bash
# runs the integration tests against a throwaway postgres cluster: initdb in a temp dir on a spare port, a scram user
# and an md5 user on one database, then stop and remove it all. PG_BIN is the postgres bin directory when it isn't on
# PATH
set -euo pipefail
cd "$(dirname "$0")/.."
bin="${PG_BIN:-}"
run() { if [[ -n "$bin" ]]; then "$bin/$1" "${@:2}"; else "$@"; fi; }
port="${PG_TEST_PORT:-55451}"
dir="$(mktemp -d)"
trap 'run pg_ctl -D "$dir/data" -m immediate stop > /dev/null 2>&1 || true; rm -rf "$dir"' EXIT
run initdb -D "$dir/data" -U pgt_admin --auth=trust -E UTF8 --no-locale > /dev/null
# the admin needs no password from this host; every test user needs its own
printf 'host all pgt_admin 127.0.0.1/32 trust\nhost all all 127.0.0.1/32 md5\n' > "$dir/data/pg_hba.conf"
# some builds default the socket to a directory the user can't write
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) sock="" ;;
  *) sock=" -c unix_socket_directories=$dir" ;;
esac
run pg_ctl -D "$dir/data" -o "-p $port -c listen_addresses=127.0.0.1$sock" -l "$dir/log" -w start > /dev/null \
  || { cat "$dir/log" >&2; exit 1; }
run psql -h 127.0.0.1 -p "$port" -U pgt_admin -d postgres -X -q -v ON_ERROR_STOP=1 <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE pgt_scram LOGIN PASSWORD 'scram-pass';
SET password_encryption = 'md5';
CREATE ROLE pgt_md5 LOGIN PASSWORD 'md5-pass';
CREATE DATABASE pg_test OWNER pgt_scram;
GRANT CONNECT, TEMP ON DATABASE pg_test TO pgt_md5;
-- defaults unlike the client's session settings, so the tests show its own win
ALTER DATABASE pg_test SET bytea_output = 'escape';
ALTER DATABASE pg_test SET extra_float_digits = 0;
ALTER DATABASE pg_test SET DateStyle = 'SQL, DMY';
ALTER DATABASE pg_test SET TimeZone = 'Australia/Perth';
SQL
PG_TEST_URL="postgres://pgt_scram:scram-pass@127.0.0.1:$port/pg_test" \
PG_TEST_MD5_URL="postgres://pgt_md5:md5-pass@127.0.0.1:$port/pg_test" \
  go test -count=1 -run Integration ${PG_TEST_FLAGS:-} ./...
