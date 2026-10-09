#!/bin/sh
# Interop driver built on curl.
#
# Usage:
#   curl-driver.sh BASE_URL PROTOCOL SCENARIO [key=value ...]
#
# Prints exactly one observation line on stdout:
#   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
#
# The harness (interop/src/client.rs) decides whether the observation is
# acceptable; this script only reports what curl saw. Expectations must never
# be duplicated here.
#
# curl cannot observe response trailers or 1xx informational responses, so the
# scenario set is declared accordingly in the client spec. Guessing would turn
# a tooling limitation into a false server bug.

set -eu

# Readiness probe: the container is considered usable when this prints nothing
# and exits 0. Keeping it trivial means a driver that cannot even run its own
# shell is reported as a start failure rather than as a matrix of errors.
# The HTTP/3 image carries a separately built curl; the HTTP/1+HTTP/2 image uses
# whatever curl the base image provides.
CURL_BIN="${CURL_BIN:-curl}"

if [ "${1:-}" = "--selftest" ]; then
	command -v "$CURL_BIN" >/dev/null 2>&1 || exit 1
	command -v sha256sum >/dev/null 2>&1 || exit 1
	exit 0
fi

# With no arguments this script is the container's main process. It announces
# readiness and then idles, because the harness reuses one container for every
# scenario and execs into it. Keeping the idle mode here rather than overriding
# the command from outside means the image entrypoint can stay the driver.
if [ "$#" -eq 0 ]; then
	echo "interop-driver ready"
	while true; do
		sleep 3600
	done
fi

BASE="$1"
PROTO="$2"
SCENARIO="$3"
shift 3

METHOD="GET"
REQ_PATH="/small"
UPLOAD=0
COUNT=1
IDLE_MS=0

for kv in "$@"; do
	key="${kv%%=*}"
	val="${kv#*=}"
	case "$key" in
	method) METHOD="$val" ;;
	path) REQ_PATH="$val" ;;
	upload_len) UPLOAD="$val" ;;
	count) COUNT="$val" ;;
	idle_ms) IDLE_MS="$val" ;;
	*) ;; # Unknown keys are ignored so the harness can add parameters freely.
	esac
done

# Protocol flags. HTTP/2 is served as h2c (prior knowledge) so no trust anchor
# is needed; HTTP/3 is QUIC over TLS with a self-signed certificate.
case "$PROTO" in
h1)
	PROTO_FLAGS="--http1.1"
	;;
h2)
	PROTO_FLAGS="--http2-prior-knowledge"
	;;
h3)
	PROTO_FLAGS="--http3-only --insecure"
	;;
*)
	echo "curl-driver: unknown protocol $PROTO" >&2
	exit 2
	;;
esac

BODY="$(mktemp)"
ERR="$(mktemp)"
trap 'rm -f "$BODY" "$ERR"' EXIT

# Emits a body of exactly $1 bytes drawn from the shared ABCD pattern, matching
# what the server generates and what the harness hashes.
emit_pattern() {
	yes ABCD | tr -d '\n' | head -c "$1"
}

status=0
body_len=0
sha="-"
err=""

emit_failure() {
	# Normalise newlines so the single-line observation format survives.
	printf 'status=%s len=%s sha=%s trailers=0 hints=0 err=%s\n' \
		"$status" "$body_len" "$sha" "$(printf '%s' "$1" | tr '\n\r' '  ')"
	exit 0
}

case "$SCENARIO" in
abort_midstream)
	# Read a bounded prefix, then let the pipe close: curl sees EPIPE and
	# resets the stream mid-response. This is the HTTP/2 analogue of the
	# "large response abandoned by the user" regression.
	abort_after=65536
	if "$CURL_BIN" $PROTO_FLAGS -sS --max-time 30 -o /dev/null "$BASE$REQ_PATH" 2>"$ERR" \
		| head -c "$abort_after" >/dev/null; then
		:
	fi
	# The connection must still serve a fresh request.
	set +e
	meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 30 -o "$BODY" \
		-w '%{http_code} %{size_download}' "$BASE/small" 2>"$ERR")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		emit_failure "post_abort_request_failed"
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;

many_headers)
	# Built with `set --` rather than `eval`: eval re-splits every argument,
	# which corrupts the header values.
	set -- $PROTO_FLAGS -sS --max-time 30 -o "$BODY" -w '%{http_code} %{size_download}'
	i=0
	while [ "$i" -lt 200 ]; do
		set -- "$@" -H "x-interop-$(printf '%04d' "$i"): v"
		i=$((i + 1))
	done
	set +e
	meta=$("$CURL_BIN" "$@" "$BASE$REQ_PATH" 2>"$ERR")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		emit_failure "many_headers_request_failed"
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;

big_header_rejected)
	# A header block far above the server's max_header_list_size. curl
	# buffers the response; the request is expected to be refused.
	big=$(emit_pattern 32768)
	set +e
	meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 30 -o "$BODY" \
		-w '%{http_code} %{size_download}' -H "x-big: $big" \
		"$BASE$REQ_PATH" 2>"$ERR")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		# A refused request may surface as a transport error rather than a
		# status; status=0 tells the harness "no response", which counts as
		# a conforming refusal.
		emit_failure "big_header_refused"
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;

long_uri)
	# A long query string rather than a long path, so the route still matches.
	long=$(emit_pattern 8192)
	set +e
	meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 30 -o "$BODY" \
		-w '%{http_code} %{size_download}' "$BASE$REQ_PATH?$long" 2>"$ERR")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		emit_failure "long_uri_request_failed"
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;

idle_reuse)
	# curl opens a connection per invocation, so "reuse" here means the
	# server must accept a fresh connection cleanly after a previous one has
	# gone idle past its timeout.
	sleep "$(awk "BEGIN{printf \"%.3f\", $IDLE_MS/1000}")"
	set +e
	meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 30 -o "$BODY" \
		-w '%{http_code} %{size_download}' "$BASE$REQ_PATH" 2>"$ERR")
	rc=$?
	set -e
	if [ "$rc" -ne 0 ]; then
		emit_failure "post_idle_request_failed"
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;

*)
	# Generic single-request path.
	if [ "$UPLOAD" -gt 0 ]; then
		emit_pattern "$UPLOAD" >"$BODY.in"
		set +e
		meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 60 -o "$BODY" \
			-w '%{http_code} %{size_download}' \
			-X "$METHOD" --data-binary "@$BODY.in" \
			"$BASE$REQ_PATH" 2>"$ERR")
		rc=$?
		set -e
		rm -f "$BODY.in"
		if [ "$rc" -ne 0 ]; then
			emit_failure "upload_request_failed"
		fi
	else
		set +e
		meta=$("$CURL_BIN" $PROTO_FLAGS -sS --max-time 60 -o "$BODY" \
			-w '%{http_code} %{size_download}' \
			-X "$METHOD" "$BASE$REQ_PATH" 2>"$ERR")
		rc=$?
		set -e
		if [ "$rc" -ne 0 ]; then
			emit_failure "request_failed"
		fi
	fi
	status=$(printf '%s' "$meta" | cut -d' ' -f1)
	body_len=$(printf '%s' "$meta" | cut -d' ' -f2)
	sha=$(sha256sum "$BODY" | cut -d' ' -f1)
	;;
esac

printf 'status=%s len=%s sha=%s trailers=0 hints=0 err=\n' "$status" "$body_len" "$sha"
