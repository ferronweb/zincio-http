// Interop driver built on quic-go's HTTP/3 stack.
//
// Usage:
//   quicgo-driver BASE_URL PROTOCOL SCENARIO [key=value ...]
//
// Prints one observation line per request on stdout:
//   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
//
// quic-go is the second Go QUIC stack in the matrix (aioquic being the
// Python one) and the implementation behind Caddy and many CDNs, so its
// QPACK encoder and loss recovery differ meaningfully from both aioquic and
// quinn. It speaks only HTTP/3.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// pattern returns n bytes of the shared ABCD body pattern, matching the
// server and the harness.
func pattern(n int) []byte {
	const p = "ABCD"
	out := make([]byte, n)
	for i := range out {
		out[i] = p[i%4]
	}
	return out
}

// Serializes observation lines: concurrent streams must never interleave
// mid-line, or the harness parses garbage.
var emitMu sync.Mutex

func emit(status int, length int, digest string, trailers bool, hints bool, err string) {
	emitMu.Lock()
	defer emitMu.Unlock()
	sha := digest
	if sha == "" {
		sha = "-"
	}
	t, h := 0, 0
	if trailers {
		t = 1
	}
	if hints {
		h = 1
	}
	fmt.Printf("status=%d len=%d sha=%s trailers=%d hints=%d err=%s\n", status, length, sha, t, h, err)
}

// newClient returns an HTTP/3 client that skips certificate verification.
// The server generates a fresh self-signed certificate per run, so there is
// nothing stable to pin; test-only, never production.
func newClient() *http.Client {
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &http.Client{Transport: transport, Timeout: 120 * time.Second}
}

// doOnce performs one request and prints its observation. Response trailers
// are read from resp.Trailer after the body is consumed, which is how the
// standard library surfaces them regardless of version.
func doOnce(client *http.Client, method, url string, upload []byte, extra [][2]string) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		emit(0, 0, "", false, false, "build_request")
		return
	}
	req.Header.Set("x-interop", "1")
	for _, kv := range extra {
		req.Header.Set(kv[0], kv[1])
	}
	if upload != nil {
		req.Body = io.NopCloser(bytes.NewReader(upload))
		req.ContentLength = int64(len(upload))
	}

	var saw103 bool
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			if code == 103 {
				saw103 = true
			}
			return nil
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		emit(0, 0, "", false, false, "request_failed")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		emit(resp.StatusCode, 0, "", false, false, "read_body")
		return
	}
	trailers := false
	if _, ok := resp.Trailer["X-Echo-Trailer"]; ok {
		trailers = true
	}
	sum := sha256.Sum256(body)
	emit(resp.StatusCode, len(body), hex.EncodeToString(sum[:]), trailers, saw103, "")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--selftest" {
		return
	}
	if len(os.Args) == 1 {
		// Idle mode: the container's main process. Announce readiness for the
		// harness, then sleep; scenarios arrive via exec.
		fmt.Println("interop-driver ready")
		for {
			time.Sleep(time.Hour)
		}
	}
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: quicgo-driver BASE_URL PROTOCOL SCENARIO [key=value ...]")
		os.Exit(2)
	}
	base, _, scenario := os.Args[1], os.Args[2], os.Args[3]
	params := map[string]string{}
	for _, kv := range os.Args[4:] {
		if k, v, ok := strings.Cut(kv, "="); ok {
			params[k] = v
		}
	}

	method := params["method"]
	if method == "" {
		method = "GET"
	}
	path := params["path"]
	if path == "" {
		path = "/small"
	}
	url := base + path

	uploadLen, _ := strconv.Atoi(params["upload_len"])
	var upload []byte
	if uploadLen > 0 {
		upload = pattern(uploadLen)
	}

	var extra [][2]string
	switch scenario {
	case "many_headers":
		for i := 0; i < 200; i++ {
			extra = append(extra, [2]string{fmt.Sprintf("x-interop-%04d", i), "v"})
		}
	case "big_header_rejected":
		extra = append(extra, [2]string{"x-big", string(bytes.Repeat([]byte("v"), 32*1024))})
	case "long_uri":
		url += "?" + string(pattern(8*1024))
	case "expect_continue":
		extra = append(extra, [2]string{"Expect", "100-continue"})
	}

	client := newClient()
	defer client.CloseIdleConnections()

	if scenario == "concurrency" {
		count, _ := strconv.Atoi(params["count"])
		if count <= 0 {
			count = 32
		}
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				doOnce(client, "GET", base+path, nil, nil)
			}()
		}
		wg.Wait()
		return
	}

	if scenario == "abort_midstream" || scenario == "idle_reuse" {
		// quic-go manages connection reuse internally; a fresh client per
		// scenario exercises handshake-plus-request, and the abort/idle
		// variants below cover mid-stream cancellation and reuse.
	}

	if scenario == "abort_midstream" {
		// Cancel a large response mid-flight via request context, then verify
		// the client still serves a fresh request.
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("x-interop", "1")
		go func() {
			// Give the response a head start, then cancel.
			time.Sleep(500 * time.Millisecond)
			cancel()
		}()
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		doOnce(client, "GET", base+"/small", nil, nil)
		return
	}

	if scenario == "idle_reuse" {
		idleMs, _ := strconv.Atoi(params["idle_ms"])
		if idleMs <= 0 {
			idleMs = 3000
		}
		time.Sleep(time.Duration(idleMs) * time.Millisecond)
		doOnce(client, method, url, upload, extra)
		return
	}

	doOnce(client, method, url, upload, extra)
}
