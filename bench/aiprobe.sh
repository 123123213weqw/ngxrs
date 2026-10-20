#!/usr/bin/env bash
# Dump real nginx's autoindex HTML for the exact file set autoindex.t creates,
# so the renderer can be written against observed bytes instead of guesswork.
set -uo pipefail

ROOT=/home/wzu/ngxrs
RUN=$ROOT/bench/run
BASE=/tmp/aiprobe
PORT=18931
D=$BASE/www

rm -rf "$BASE"; mkdir -p "$D/utf8" "$BASE/logs"; : >"$BASE/logs/access.log"; : >"$BASE/logs/error.log"
mkdir "$D/test-dir"
ln -s "$D/test-dir" "$D/test-dir-link"
: >"$D/test-file"
ln -s "$D/test-file" "$D/test-file-link"
: >"$D/test-colon:blah"
: >"$D/test-long-$(printf '0%.0s' $(seq 1 50))"
: >"$D/test-long-$(printf '>%.0s' $(seq 1 50))"
: >"$D/test-escape-url-%"
: >"$D/test-escape-url2-?"
: >"$D/test-escape-html-<>&"
UTF=$(printf '\321\204')
: >"$D/utf8/test-utf8-$UTF$UTF$UTF"
: >"$D/utf8/test-utf8-$(for i in $(seq 1 45); do printf '%s' "$UTF"; done)"
: >"$D/utf8/test-utf8-<>&-$UTF"
: >"$D/utf8/test-utf8-<>&-$(for i in $(seq 1 45); do printf '%s' "$UTF"; done)"
: >"$D/utf8/test-utf8-$UTF$UTF$UTF-$(printf '>%.0s' $(seq 1 45))"
mkdir "$D/test-dir-escape-<>&"

cat >"$BASE/nginx.conf" <<EOF
worker_processes 1;
daemon off;
pid $BASE/nginx.pid;
error_log $BASE/err.log warn;
events { worker_connections 1024; }
http {
    include $ROOT/conf/mime.types;
    default_type application/octet-stream;
    server {
        listen 127.0.0.1:$PORT;
        server_name localhost;
        location / { root $D; autoindex on; }
        location /utf8/ { root $D; autoindex on; charset utf-8; }
    }
}
EOF

"$ROOT/../nginx-baseline/sbin/nginx" -c "$BASE/nginx.conf" -p "$BASE" 2>"$BASE/start.err" &
sleep 1.5

echo "===== ROOT ====="
curl -s "http://127.0.0.1:$PORT/" | tee "$BASE/out.html"
echo "===== UTF8 ====="
curl -s "http://127.0.0.1:$PORT/utf8/" | tee "$BASE/out-utf8.html"
echo "===== TITLE ====="
curl -s "http://127.0.0.1:$PORT/test-dir-escape-%3C%3E%26/" | head -3
echo "===== DONE ====="

[ -f "$BASE/nginx.pid" ] && kill "$(cat "$BASE/nginx.pid")" 2>/dev/null

# --- byte-for-byte comparison against ngxrs on the same directory ---
NGP=$((PORT + 1))
cat >"$BASE/ngxrs.conf" <<EOF2
worker_processes 1;
daemon off;
pid $BASE/ngxrs.pid;
error_log $BASE/ngxrs-err.log warn;
events { worker_connections 1024; }
http {
    include $ROOT/conf/mime.types;
    default_type application/octet-stream;
    access_log off;
    server {
        listen 127.0.0.1:$NGP;
        server_name localhost;
        location / { root $D; autoindex on; }
        location /utf8/ { root $D; autoindex on; charset utf-8; }
    }
}
EOF2
"$ROOT/target/release/ngxrs" -c "$BASE/ngxrs.conf" -p "$ROOT" >/dev/null 2>&1 &
sleep 1.5
curl -s "http://127.0.0.1:$NGP/" -o "$BASE/ours.html"
curl -s "http://127.0.0.1:$NGP/utf8/" -o "$BASE/ours-utf8.html"
[ -f "$BASE/ngxrs.pid" ] && kill "$(cat "$BASE/ngxrs.pid")" 2>/dev/null

echo "===== BYTE DIFF root ====="
diff <(cat "$BASE/out.html") <(cat "$BASE/ours.html") && echo "IDENTICAL"
echo "===== BYTE DIFF utf8 ====="
diff <(cat "$BASE/out-utf8.html" 2>/dev/null) <(cat "$BASE/ours-utf8.html") && echo "IDENTICAL"
