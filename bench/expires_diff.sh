#!/usr/bin/env bash
# Differential check for `expires`, which has no official nginx-tests file
# (`expires.t` does not exist upstream -- the copy in some checkouts is a 404
# body from a failed download).
#
# Runs the identical config on nginx and on ngxrs and diffs the response
# headers, with the variable parts (Date/Expires) compared by shape rather than
# by value so a one-second clock skew cannot make the run flap.
set -uo pipefail

ROOT=/home/wzu/ngxrs
BASE=/tmp/expprobe
PORT_N=18841
PORT_X=18842
EXTRA=$((PORT_N + 10))
EXTRA_X=$((PORT_X + 10))

rm -rf "$BASE"; mkdir -p "$BASE/logs" "$BASE/www"
: >"$BASE/logs/access.log"; : >"$BASE/logs/error.log"
# A real file for every path that should serve content, so the comparison is
# about `expires` and not about 404 handling. `/missing` deliberately has none:
# nginx applies expires only to the statuses in ngx_http_headers_filter_module's
# list (200/201/204/206/301/302/303/304/307/308), never to a 404.
for f in off epoch max 500 1h neg at atm mod up r1h; do
    echo "0123456789" >"$BASE/www/$f"
    touch -d '2020-01-02 03:04:05 UTC' "$BASE/www/$f"
done

gen() {
    local port=$1 extra=$2
    cat <<EOF
worker_processes 1;
daemon off;
pid $BASE/pid-$port;
error_log $BASE/err-$port.log warn;
events { worker_connections 256; }
http {
    include $ROOT/conf/mime.types;
    default_type text/plain;
    access_log off;
    server {
        listen 127.0.0.1:$port;
        root $BASE/www;
        location /off   { expires off; }
        location /epoch { expires epoch; }
        location /max   { expires max; }
        location /500   { expires 500; }
        location /1h    { expires 1h; }
        location /neg   { expires -1h; }
        location /at    { expires @15h; }
        location /atm   { expires @15h30m; }
        location /mod   { expires modified +1h; }
        location /up    { expires 1h; proxy_pass http://127.0.0.1:$extra/cc; }
        location /r1h   { expires 1h; return 200 "x"; }
        location /missing { expires 1h; }
    }
    server {
        listen 127.0.0.1:$extra;
        location /cc { add_header Cache-Control "public, max-age=99" always; return 200 "x"; }
    }
}
EOF
}

gen "$PORT_N" "$EXTRA" >"$BASE/nginx.conf"
gen "$PORT_X" "$EXTRA_X" >"$BASE/ngxrs.conf"

"$ROOT/../nginx-baseline/sbin/nginx" -c "$BASE/nginx.conf" -p "$BASE" >/dev/null 2>&1 &
"$ROOT/target/release/ngxrs" -c "$BASE/ngxrs.conf" -p "$ROOT" >/dev/null 2>&1 &
sleep 2

# Compare only the headers that `expires` is responsible for.
grab() {
    curl -sS -D - -o /dev/null "http://127.0.0.1:$1$2" 2>/dev/null \
        | tr -d '\r' \
        | grep -iE '^(Expires|Cache-Control):' \
        | while IFS= read -r line; do
            # Normalise the two date formats' exact instants; keep the shape.
            echo "$line" | sed -E 's/[0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT/<DATE>/'
          done
}

fail=0
for path in /off /epoch /max /500 /1h /neg /at /atm /mod /up /r1h /missing; do
    a=$(grab "$PORT_N" "$path")
    b=$(grab "$PORT_X" "$path")
    if [ "$a" = "$b" ]; then
        printf 'SAME   %-6s %s\n' "$path" "$(echo "$a" | tr '\n' ' ' | sed 's/  */ /g')"
    else
        printf 'DIFF   %-6s\n  nginx: %s\n  ngxrs: %s\n' "$path" \
            "$(echo "$a" | tr '\n' ' ')" "$(echo "$b" | tr '\n' ' ')"
        fail=$((fail + 1))
    fi
done

[ -f "$BASE/pid-$PORT_N" ] && kill "$(cat "$BASE/pid-$PORT_N")" 2>/dev/null
[ -f "$BASE/pid-$PORT_X" ] && kill "$(cat "$BASE/pid-$PORT_X")" 2>/dev/null
echo "diff_total=$fail"
