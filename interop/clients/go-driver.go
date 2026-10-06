// Interop driver built on Go's net/http.
//
// Usage:
//   go-driver BASE_URL PROTOCOL SCENARIO [key=value ...]
//
// Prints one observation line per request on stdout:
//   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
//
// Go is the third HPACK implementation in the matrix (after nghttp2-via-curl
// and the in-repo codec): x/net/http2 encodes headers differently enough that
// encoder-behavior bugs surface here first. It also drives real concurrent
// streams with goroutines, so it shares the concurrency scenario with aioquic
// rather than leaving HTTP/2 concurrency to a single client.
//
// Like curl it cannot usefully observe response trailers or 1xx responses
// through net/http's API, so those capabilities are not claimed.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
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

// newClient returns an HTTP client for protocol. HTTP/2 is served as h2c
// (prior knowledge, no TLS), which needs x/net with AllowHTTP; anything else
// uses the standard transport.
func newClient(protocol, base string) (*http.Client, error) {
	if protocol == "h2" {
		transport := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 10 * time.Second}
				return dialer.DialContext(ctx, network, addr)
			},
		}
		// h2c prior knowledge speaks to the authority host, which from inside
		// the container is the gateway alias.
		return &http.Client{Transport: transport, Timeout: 120 * time.Second}, nil
	}
	return &http.Client{Timeout: 120 * time.Second}, nil
}

// doOnce performs one request and prints its observation.
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

	// Observe informational responses. Go surfaces every 1xx through this
	// hook on both HTTP/1.1 and HTTP/2, which is what lets this driver report
	// 103 Early Hints -- something curl fundamentally cannot do.
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
	sum := sha256.Sum256(body)
	emit(resp.StatusCode, len(body), hex.EncodeToString(sum[:]), false, saw103, "")
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
		fmt.Fprintln(os.Stderr, "usage: go-driver BASE_URL PROTOCOL SCENARIO [key=value ...]")
		os.Exit(2)
	}
	base, protocol, scenario := os.Args[1], os.Args[2], os.Args[3]
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

	client, err := newClient(protocol, base)
	if err != nil {
		emit(0, 0, "", false, false, "client_setup")
		return
	}

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

	doOnce(client, method, url, upload, extra)
}
