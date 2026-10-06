import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.Buffer;
import okio.BufferedSource;

/**
 * Interop driver built on OkHttp (the JVM/Android HTTP stack).
 *
 * <p>Usage:
 * {@code OkHttpDriver BASE_URL PROTOCOL SCENARIO [key=value ...]}
 *
 * <p>Prints one observation line per request on stdout:
 * {@code status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>}
 *
 * <p>HTTP/2 is spoken as h2c with prior knowledge: OkHttp only negotiates H2
 * over TLS by default, so the client is built with
 * {@code Protocol.H2_PRIOR_KNOWLEDGE} for cleartext URLs.
 */
public final class OkHttpDriver {
    private OkHttpDriver() {}

    /** The shared ABCD body pattern, matching the server and the harness. */
    static byte[] pattern(int n) {
        byte[] out = new byte[n];
        byte[] p = {'A', 'B', 'C', 'D'};
        for (int i = 0; i < n; i++) {
            out[i] = p[i % 4];
        }
        return out;
    }

    static String shaHex(byte[] body) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(body);
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    static synchronized void emit(
            int status, int length, String digest,
            boolean trailers, boolean hints, String err) {
        System.out.printf(
                "status=%d len=%d sha=%s trailers=%d hints=%d err=%s%n",
                status, length, digest.isEmpty() ? "-" : digest,
                trailers ? 1 : 0, hints ? 1 : 0, err);
    }

    static OkHttpClient newClient(String protocol) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(120, TimeUnit.SECONDS)
                .callTimeout(120, TimeUnit.SECONDS);
        if (protocol.equals("h2")) {
            builder.protocols(java.util.Collections.singletonList(
                    Protocol.H2_PRIOR_KNOWLEDGE));
        }
        return builder.build();
    }

    static void doOnce(
            OkHttpClient client, String method, String url,
            byte[] upload, List<String[]> extra) {
        try {
            Request.Builder builder = new Request.Builder()
                    .url(url)
                    .header("x-interop", "1");
            for (String[] kv : extra) {
                builder.header(kv[0], kv[1]);
            }
            if (upload != null) {
                builder.method(
                        method,
                        RequestBody.create(
                                upload,
                                MediaType.parse("application/octet-stream")));
            } else if (method.equals("POST")) {
                builder.method(method, RequestBody.create(
                        new byte[0], MediaType.parse("application/octet-stream")));
            } else {
                builder.method(method, null);
            }

            try (Response response = client.newCall(builder.build()).execute()) {
                byte[] body;
                try (BufferedSource source = response.body().source()) {
                    Buffer buffer = new Buffer();
                    buffer.writeAll(source);
                    body = buffer.readByteArray();
                }
                // Response trailers, if the version delivering them populates
                // the trailers source after the body is consumed.
                boolean trailers = false;
                try {
                    okhttp3.Headers trailerHeaders = response.trailers();
                    trailers = trailerHeaders.get("x-echo-trailer") != null;
                } catch (Exception ignored) {
                    // No trailers available on this path.
                }
                emit(response.code(), body.length, shaHex(body),
                        trailers, false, "");
            }
        } catch (Exception e) {
            emit(0, 0, "", false, false,
                    e.getClass().getSimpleName());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--selftest")) {
            return;
        }
        if (args.length == 0) {
            // Idle mode: the container's main process. Announce readiness for
            // the harness, then sleep; scenarios arrive via exec.
            System.out.println("interop-driver ready");
            // ignore checked exception on sleep: park instead
            Object lock = new Object();
            //noinspection InfiniteLoopStatement
            while (true) {
                synchronized (lock) {
                    lock.wait(3600_000);
                }
            }
        }
        if (args.length < 3) {
            System.err.println(
                    "usage: OkHttpDriver BASE_URL PROTOCOL SCENARIO [key=value ...]");
            System.exit(2);
        }
        String base = args[0];
        String protocol = args[1];
        String scenario = args[2];
        java.util.Map<String, String> params = new java.util.HashMap<>();
        for (int i = 3; i < args.length; i++) {
            int eq = args[i].indexOf('=');
            if (eq >= 0) {
                params.put(args[i].substring(0, eq), args[i].substring(eq + 1));
            }
        }

        String method = params.getOrDefault("method", "GET");
        String path = params.getOrDefault("path", "/small");
        String url = base + path;

        int uploadLen;
        try {
            uploadLen = Integer.parseInt(params.getOrDefault("upload_len", "0"));
        } catch (NumberFormatException e) {
            uploadLen = 0;
        }
        byte[] upload = uploadLen > 0 ? pattern(uploadLen) : null;

        List<String[]> extra = new ArrayList<>();
        switch (scenario) {
            case "many_headers":
                for (int i = 0; i < 200; i++) {
                    extra.add(new String[]{
                            String.format("x-interop-%04d", i), "v"});
                }
                break;
            case "big_header_rejected": {
                StringBuilder big = new StringBuilder(32 * 1024);
                for (int i = 0; i < 32 * 1024; i++) {
                    big.append('v');
                }
                extra.add(new String[]{"x-big", big.toString()});
                break;
            }
            case "long_uri": {
                StringBuilder query = new StringBuilder(8 * 1024);
                byte[] p = {'A', 'B', 'C', 'D'};
                for (int i = 0; i < 8 * 1024; i++) {
                    query.append((char) p[i % 4]);
                }
                url += "?" + query;
                break;
            }
            case "expect_continue":
                extra.add(new String[]{"Expect", "100-continue"});
                break;
            default:
                break;
        }

        OkHttpClient client = newClient(protocol);

        if (scenario.equals("concurrency")) {
            int count;
            try {
                count = Integer.parseInt(params.getOrDefault("count", "32"));
            } catch (NumberFormatException e) {
                count = 32;
            }
            if (count <= 0) {
                count = 32;
            }
            CountDownLatch latch = new CountDownLatch(count);
            String finalUrl = base + path;
            for (int i = 0; i < count; i++) {
                new Thread(() -> {
                    try {
                        doOnce(client, "GET", finalUrl, null,
                                java.util.Collections.emptyList());
                    } finally {
                        latch.countDown();
                    }
                }).start();
            }
            latch.await(120, TimeUnit.SECONDS);
            return;
        }

        doOnce(client, method, url, upload, extra);
    }
}
