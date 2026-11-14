#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <lsquic.h>
#include <lsxpack_header.h>

#include "endpoint.h"

// How long the QUIC handshake may take.
#define HANDSHAKE_DEADLINE_MS 15000

// Cap each poll wait. `lsquic_engine_earliest_adv_tick()` can ask for a long
// sleep, but pacing and delayed ACK timers need the engine ticked promptly.
#define MAX_POLL_WAIT_MS 20

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

uint64_t driver_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static char *driver_strdup(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    size_t len = strlen(s);
    char *copy = malloc(len + 1);
    if (copy != NULL) {
        memcpy(copy, s, len + 1);
    }
    return copy;
}

static void driver_result_set_error(driver_result_t *result, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) {
        result->error = driver_strdup("internal_error");
    } else {
        result->error = malloc((size_t)needed + 1);
        if (result->error != NULL) {
            vsnprintf(result->error, (size_t)needed + 1, fmt, args);
        }
    }
    va_end(args);
}

void driver_result_free(driver_result_t *result) {
    if (result != NULL) {
        free(result->error);
        result->error = NULL;
    }
}

static int driver_log_buf(void *logger_ctx, const char *buf, size_t len) {
    (void)logger_ctx;
    return (int)fwrite(buf, 1, len, stderr);
}

static const struct lsquic_logger_if driver_logger_if = {
    .log_buf = driver_log_buf,
};

static driver_result_t driver_result_ok(void) {
    return (driver_result_t){.error = NULL};
}

// ---------------------------------------------------------------------------
// Byte buffers and response map
// ---------------------------------------------------------------------------

int driver_buf_append(driver_buf_t *buf, const void *data, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (buf->len > SIZE_MAX - len) {
        return -1;
    }
    size_t needed = buf->len + len;
    if (needed > buf->capacity) {
        size_t new_capacity = buf->capacity == 0 ? 256 : buf->capacity;
        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        unsigned char *new_data = realloc(buf->data, new_capacity);
        if (new_data == NULL) {
            return -1;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

void driver_buf_free(driver_buf_t *buf) {
    if (buf != NULL) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
    }
}

void driver_resp_free(driver_resp_t *resp) {
    if (resp != NULL) {
        driver_buf_free(&resp->body);
        resp->status = 0;
        resp->trailers = false;
        resp->hints = false;
        resp->done = false;
        resp->reset = false;
    }
}

static driver_resps_node_t *driver_resps_node_alloc(uint64_t id, driver_resp_t *resp) {
    driver_resps_node_t *node = malloc(sizeof(*node));
    if (node == NULL) {
        return NULL;
    }
    node->id = id;
    node->resp = resp;
    node->left = NULL;
    node->right = NULL;
    return node;
}

int driver_resps_insert(driver_resps_t *resps, uint64_t id, driver_resp_t *resp) {
    driver_resps_node_t **slot = &resps->root;
    while (*slot != NULL) {
        if (id < (*slot)->id) {
            slot = &(*slot)->left;
        } else if (id > (*slot)->id) {
            slot = &(*slot)->right;
        } else {
            (*slot)->resp = resp;
            return 0;
        }
    }
    *slot = driver_resps_node_alloc(id, resp);
    return *slot == NULL ? -1 : 0;
}

static driver_resps_node_t *driver_resps_detach_min(driver_resps_node_t *node,
                                                     driver_resps_node_t **min_out) {
    if (node->left == NULL) {
        *min_out = node;
        return node->right;
    }
    node->left = driver_resps_detach_min(node->left, min_out);
    return node;
}

static driver_resps_node_t *driver_resps_delete_node(driver_resps_node_t *node,
                                                      uint64_t id,
                                                      driver_resp_t **resp_out) {
    if (node == NULL) {
        return NULL;
    }
    if (id < node->id) {
        node->left = driver_resps_delete_node(node->left, id, resp_out);
    } else if (id > node->id) {
        node->right = driver_resps_delete_node(node->right, id, resp_out);
    } else {
        *resp_out = node->resp;
        if (node->left == NULL) {
            driver_resps_node_t *right = node->right;
            free(node);
            return right;
        }
        if (node->right == NULL) {
            driver_resps_node_t *left = node->left;
            free(node);
            return left;
        }
        driver_resps_node_t *min_node = NULL;
        node->right = driver_resps_detach_min(node->right, &min_node);
        min_node->left = node->left;
        min_node->right = node->right;
        free(node);
        return min_node;
    }
    return node;
}

driver_resp_t *driver_resps_delete(driver_resps_t *resps, uint64_t id) {
    driver_resp_t *resp = NULL;
    resps->root = driver_resps_delete_node(resps->root, id, &resp);
    return resp;
}

driver_resp_t *driver_resps_get(const driver_resps_t *resps, uint64_t id) {
    const driver_resps_node_t *node = resps->root;
    while (node != NULL) {
        if (id < node->id) {
            node = node->left;
        } else if (id > node->id) {
            node = node->right;
        } else {
            return node->resp;
        }
    }
    return NULL;
}

static void driver_resps_node_free(driver_resps_node_t *node) {
    if (node == NULL) {
        return;
    }
    driver_resps_node_free(node->left);
    driver_resps_node_free(node->right);
    driver_resp_free(node->resp);
    free(node->resp);
    free(node);
}

void driver_resps_free(driver_resps_t *resps) {
    if (resps != NULL) {
        driver_resps_node_free(resps->root);
        resps->root = NULL;
    }
}

static bool driver_resps_node_all_done(const driver_resps_node_t *node) {
    if (node == NULL) {
        return true;
    }
    if (!node->resp->done) {
        return false;
    }
    return driver_resps_node_all_done(node->left) &&
           driver_resps_node_all_done(node->right);
}

static bool driver_resps_all_done(const driver_resps_t *resps) {
    return driver_resps_node_all_done(resps->root);
}

// ---------------------------------------------------------------------------
// Request/response header lists
// ---------------------------------------------------------------------------

typedef struct {
    const char *name;
    const char *value;
} driver_kv_t;

typedef struct {
    struct lsxpack_header *headers;
    size_t count;
    char *buf;
} driver_header_list_t;

#define DRIVER_HEADER_LIST_NULL ((driver_header_list_t){NULL, 0, NULL})

static void driver_header_list_free(driver_header_list_t *list) {
    free(list->headers);
    free(list->buf);
    list->headers = NULL;
    list->buf = NULL;
    list->count = 0;
}

static int driver_header_list_build(driver_header_list_t *out,
                                    const driver_kv_t *kvs, size_t count) {
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        size_t name_len = strlen(kvs[i].name);
        size_t value_len = strlen(kvs[i].value);
        if (name_len > LSXPACK_MAX_STRLEN || value_len > LSXPACK_MAX_STRLEN ||
            total > SIZE_MAX - name_len - value_len) {
            return -1;
        }
        total += name_len + value_len;
    }

    struct lsxpack_header *headers = calloc(count, sizeof(*headers));
    char *buf = malloc(total == 0 ? 1 : total);
    if (headers == NULL || buf == NULL) {
        free(headers);
        free(buf);
        return -1;
    }

    size_t offset = 0;
    for (size_t i = 0; i < count; i++) {
        size_t name_len = strlen(kvs[i].name);
        size_t value_len = strlen(kvs[i].value);
        memcpy(buf + offset, kvs[i].name, name_len);
        memcpy(buf + offset + name_len, kvs[i].value, value_len);
        lsxpack_header_set_offset2(&headers[i], buf, offset, name_len,
                                   offset + name_len, value_len);
        offset += name_len + value_len;
    }

    out->headers = headers;
    out->count = count;
    out->buf = buf;
    return 0;
}

// ---------------------------------------------------------------------------
// Decoding response headers
// ---------------------------------------------------------------------------

typedef struct {
    driver_resp_t *resp;
    bool has_status;
    uint16_t status;
    char *buf;
    size_t capacity;
    struct lsxpack_header xhdr;
} driver_hset_t;

static driver_hset_t *driver_hset_new(driver_resp_t *resp) {
    driver_hset_t *hset = calloc(1, sizeof(*hset));
    if (hset != NULL) {
        hset->resp = resp;
    }
    return hset;
}

static void driver_hset_free(void *hset_p) {
    driver_hset_t *hset = hset_p;
    if (hset != NULL) {
        free(hset->buf);
        free(hset);
    }
}

static struct lsxpack_header *driver_hsi_prepare_decode(void *hset_p,
                                                        struct lsxpack_header *hdr,
                                                        size_t space) {
    driver_hset_t *hset = hset_p;
    size_t wanted = space == 0 ? 256 : space;
    if (wanted > LSXPACK_MAX_STRLEN) {
        return NULL;
    }
    if (wanted < 256) {
        wanted = 256;
    }

    if (hdr == NULL) {
        if (hset->capacity < wanted) {
            char *buf = realloc(hset->buf, wanted);
            if (buf == NULL) {
                return NULL;
            }
            hset->buf = buf;
            hset->capacity = wanted;
        }
        lsxpack_header_prepare_decode(&hset->xhdr, hset->buf, 0, hset->capacity);
        return &hset->xhdr;
    }

    // The decoder needs a bigger buffer for the header currently being
    // decoded. Preserve the partially decoded offsets and only grow capacity.
    size_t new_capacity = hset->capacity == 0 ? wanted : hset->capacity;
    while (new_capacity < wanted) {
        if (new_capacity > LSXPACK_MAX_STRLEN / 2) {
            new_capacity = wanted;
            break;
        }
        new_capacity *= 2;
    }
    char *buf = realloc(hset->buf, new_capacity);
    if (buf == NULL) {
        return NULL;
    }
    hset->buf = buf;
    hset->capacity = new_capacity;
    hdr->buf = buf;
    hdr->val_len = (lsxpack_strlen_t)new_capacity;
    return hdr;
}

static bool driver_value_is_3_digits(const char *value, size_t len) {
    if (len != 3) {
        return false;
    }
    for (size_t i = 0; i < 3; i++) {
        if (value[i] < '0' || value[i] > '9') {
            return false;
        }
    }
    return true;
}

static int driver_hsi_process_header(void *hset_p, struct lsxpack_header *hdr) {
    driver_hset_t *hset = hset_p;

    if (hdr == NULL) {
        // End of one HEADERS block. A block without `:status` is a trailer
        // block; a 1xx status is informational, not the final response.
        if (hset->resp != NULL) {
            if (hset->has_status) {
                if (hset->status >= 100 && hset->status < 200) {
                    if (hset->status != 100) {
                        hset->resp->hints = true;
                    }
                } else {
                    hset->resp->status = hset->status;
                }
            } else {
                hset->resp->trailers = true;
            }
        }
        hset->has_status = false;
        return 0;
    }

    const char *name = lsxpack_header_get_name(hdr);
    const char *value = lsxpack_header_get_value(hdr);
    if (name != NULL && hdr->name_len == 7 && memcmp(name, ":status", 7) == 0 &&
        driver_value_is_3_digits(value, hdr->val_len)) {
        hset->has_status = true;
        hset->status = (uint16_t)((value[0] - '0') * 100 + (value[1] - '0') * 10 +
                                  (value[2] - '0'));
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Endpoint and stream state
// ---------------------------------------------------------------------------

typedef struct {
    driver_header_list_t headers;
    driver_header_list_t trailers;
    unsigned char *body;
    size_t body_len;
} driver_request_t;

struct driver_request_node;

typedef struct {
    driver_endpoint_t *endpoint;
    struct driver_request_node *request;
    lsquic_stream_t *stream;
    bool headers_sent;
    bool body_done;
    bool body_flushed;
    bool trailers_sent;
    bool write_done;
    bool read_done;
    size_t body_written;
} driver_stream_ctx_t;

struct driver_request_node {
    uint64_t id;
    driver_resp_t *resp;
    driver_request_t request;
    lsquic_stream_t *stream;
    bool started;
    struct driver_request_node *next;
};

typedef struct driver_request_node driver_request_node_t;

struct driver_endpoint {
    int sock;
    lsquic_engine_t *engine;
    lsquic_conn_t *conn;
    char *host;

    struct sockaddr_storage local;
    socklen_t local_len;
    struct sockaddr_storage peer;
    socklen_t peer_len;

    bool handshake_done;
    bool handshake_failed;
    bool conn_closed;

    // First error wins: callbacks can fire several times for one failure.
    char *error;

    driver_request_node_t *requests;
    uint64_t next_id;
};

static void driver_endpoint_fail(driver_endpoint_t *endpoint, const char *fmt, ...) {
    if (endpoint->error != NULL) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed >= 0) {
        endpoint->error = malloc((size_t)needed + 1);
        if (endpoint->error != NULL) {
            vsnprintf(endpoint->error, (size_t)needed + 1, fmt, args);
        }
    }
    va_end(args);
    if (endpoint->error == NULL) {
        endpoint->error = driver_strdup("internal_error");
    }
    if (endpoint->conn != NULL) {
        lsquic_conn_close(endpoint->conn);
    }
}

static driver_result_t driver_endpoint_result(driver_endpoint_t *endpoint) {
    driver_result_t result = driver_result_ok();
    if (endpoint->error != NULL) {
        driver_result_set_error(&result, "%s", endpoint->error);
    }
    return result;
}

// ---------------------------------------------------------------------------
// lsquic callbacks
// ---------------------------------------------------------------------------

static int driver_packets_out(void *ctx, const struct lsquic_out_spec *specs,
                              unsigned count) {
    driver_endpoint_t *endpoint = ctx;
    unsigned sent = 0;
    for (unsigned i = 0; i < count; i++) {
        struct msghdr msg = {0};
        msg.msg_name = (void *)specs[i].dest_sa;
        msg.msg_namelen = specs[i].dest_sa->sa_family == AF_INET
                              ? sizeof(struct sockaddr_in)
                              : sizeof(struct sockaddr_in6);
        msg.msg_iov = specs[i].iov;
        msg.msg_iovlen = specs[i].iovlen;
        if (sendmsg(endpoint->sock, &msg, 0) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return sent == 0 ? -1 : (int)sent;
        }
        sent++;
    }
    return (int)sent;
}

static struct ssl_ctx_st *driver_get_ssl_ctx(void *peer_ctx,
                                             const struct sockaddr *local) {
    (void)peer_ctx;
    (void)local;
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (ssl_ctx == NULL) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    // *CAUTION*: test-only. The scenario server generates a fresh self-signed
    // certificate per run, so there is nothing stable to pin.
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    return ssl_ctx;
}

static lsquic_conn_ctx_t *driver_endpoint_on_new_conn(void *stream_if_ctx,
                                                       lsquic_conn_t *conn) {
    driver_endpoint_t *endpoint = stream_if_ctx;
    endpoint->conn = conn;
    return (lsquic_conn_ctx_t *)endpoint;
}

static void driver_endpoint_on_hsk_done(lsquic_conn_t *conn,
                                        enum lsquic_hsk_status status) {
    driver_endpoint_t *endpoint = (driver_endpoint_t *)lsquic_conn_get_ctx(conn);
    if (endpoint == NULL) {
        return;
    }
    if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK) {
        endpoint->handshake_done = true;
    } else {
        endpoint->handshake_failed = true;
    }
}

static void driver_endpoint_on_conn_closed(lsquic_conn_t *conn) {
    driver_endpoint_t *endpoint = (driver_endpoint_t *)lsquic_conn_get_ctx(conn);
    if (endpoint != NULL) {
        endpoint->conn_closed = true;
        endpoint->conn = NULL;
        if (getenv("LSQUIC_DEBUG") != NULL) {
            char errbuf[256] = {0};
            enum LSQUIC_CONN_STATUS status =
                lsquic_conn_status(conn, errbuf, sizeof(errbuf));
            fprintf(stderr, "lsquic: conn closed status=%d msg=%s%s\n",
                    (int)status, errbuf,
                    endpoint->error != NULL ? endpoint->error : "");
        }
    }
    // lsquic asserts that the connection context is cleared before the
    // connection is destroyed.
    lsquic_conn_set_ctx(conn, NULL);
}

static void driver_endpoint_on_conncloseframe(lsquic_conn_t *conn,
                                              int app_error,
                                              uint64_t error_code,
                                              const char *reason,
                                              int reason_len) {
    driver_endpoint_t *endpoint = (driver_endpoint_t *)lsquic_conn_get_ctx(conn);
    if (endpoint == NULL || getenv("LSQUIC_DEBUG") == NULL) {
        return;
    }
    fprintf(stderr,
            "lsquic: CONNECTION_CLOSE app_error=%d code=0x%" PRIx64 " reason=%.*s\n",
            app_error, error_code, reason_len, reason != NULL ? reason : "");
}

static driver_request_node_t *driver_endpoint_next_pending(driver_endpoint_t *endpoint) {
    for (driver_request_node_t *node = endpoint->requests; node != NULL;
         node = node->next) {
        if (!node->started) {
            return node;
        }
    }
    return NULL;
}

static driver_stream_ctx_t *driver_stream_ctx_new(driver_endpoint_t *endpoint,
                                                  driver_request_node_t *node,
                                                  lsquic_stream_t *stream) {
    driver_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->endpoint = endpoint;
    ctx->request = node;
    ctx->stream = stream;
    return ctx;
}

static lsquic_stream_ctx_t *driver_endpoint_on_new_stream(void *stream_if_ctx,
                                                           lsquic_stream_t *stream) {
    driver_endpoint_t *endpoint = stream_if_ctx;
    driver_request_node_t *node = driver_endpoint_next_pending(endpoint);
    if (node == NULL) {
        // No request is waiting: the connection is going away, or lsquic
        // created a stream we never asked for. Close it rather than leak it.
        if (stream != NULL) {
            lsquic_stream_close(stream);
        }
        return NULL;
    }

    node->started = true;
    node->stream = stream;
    if (stream == NULL) {
        if (node->resp != NULL) {
            node->resp->done = true;
            node->resp->reset = true;
        }
        return NULL;
    }

    driver_stream_ctx_t *ctx = driver_stream_ctx_new(endpoint, node, stream);
    if (ctx == NULL) {
        driver_endpoint_fail(endpoint, "out_of_memory");
        lsquic_stream_close(stream);
        if (node->resp != NULL) {
            node->resp->done = true;
            node->resp->reset = true;
        }
        return NULL;
    }

    lsquic_stream_wantwrite(stream, 1);
    return (lsquic_stream_ctx_t *)ctx;
}

static void driver_drain_hsets(lsquic_stream_t *stream) {
    // Headers are classified in the hsi callbacks; claiming the set here is
    // what releases lsquic's bounded per-stream queue.
    void *hset;
    while ((hset = lsquic_stream_get_hset(stream)) != NULL) {
        driver_hset_free(hset);
    }
}

static void driver_endpoint_on_hset_in(lsquic_stream_t *stream,
                                       lsquic_stream_ctx_t *stream_ctx) {
    (void)stream_ctx;
    driver_drain_hsets(stream);
}

static void driver_endpoint_on_write(lsquic_stream_t *stream,
                                     lsquic_stream_ctx_t *stream_ctx) {
    driver_stream_ctx_t *ctx = (driver_stream_ctx_t *)stream_ctx;
    if (ctx == NULL) {
        return;
    }
    driver_endpoint_t *endpoint = ctx->endpoint;
    driver_request_node_t *node = ctx->request;
    driver_request_t *request = &node->request;

    if (!ctx->headers_sent) {
        lsquic_http_headers_t headers = {
            .count = (int)request->headers.count,
            .headers = request->headers.headers,
        };
        if (lsquic_stream_send_headers(stream, &headers, 0) != 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                lsquic_stream_wantwrite(stream, 1);
                return;
            }
            driver_endpoint_fail(endpoint, "send_headers:%s", strerror(errno));
            return;
        }
        ctx->headers_sent = true;
        // Let the header block drain before writing DATA. lsquic would also
        // cope with an immediate body write, but returning here mirrors the
        // ordering the shipped http_client example relies on.
        return;
    }

    if (!ctx->body_done) {
        while (ctx->body_written < request->body_len) {
            ssize_t written = lsquic_stream_write(
                stream, request->body + ctx->body_written,
                request->body_len - ctx->body_written);
            if (written < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    lsquic_stream_wantwrite(stream, 1);
                    return;
                }
                driver_endpoint_fail(endpoint, "write_body:%s", strerror(errno));
                return;
            }
            if (written == 0) {
                // No progress despite being called as writable. Wait for the
                // next writable event rather than spinning.
                lsquic_stream_wantwrite(stream, 1);
                return;
            }
            ctx->body_written += (size_t)written;
        }
        ctx->body_done = true;
    }

    if (request->trailers.count > 0 && !ctx->trailers_sent) {
        // lsquic buffers both the body and a following header block in the
        // same stream buffer.  Packetization only happens later, so a DATA
        // frame opened for the body would swallow the trailer block as
        // payload.  Flush the body into a DATA frame first and send the
        // trailers on the next writable turn.
        if (!ctx->body_flushed) {
            if (lsquic_stream_flush(stream) != 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    lsquic_stream_wantwrite(stream, 1);
                    return;
                }
                driver_endpoint_fail(endpoint, "flush_body:%s", strerror(errno));
                return;
            }
            ctx->body_flushed = true;
            lsquic_stream_wantwrite(stream, 1);
            return;
        }
        lsquic_http_headers_t trailers = {
            .count = (int)request->trailers.count,
            .headers = request->trailers.headers,
        };
        if (lsquic_stream_send_headers(stream, &trailers, 0) != 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                lsquic_stream_wantwrite(stream, 1);
                return;
            }
            driver_endpoint_fail(endpoint, "send_trailers:%s", strerror(errno));
            return;
        }
        ctx->trailers_sent = true;
        return;
    }

    if (!ctx->write_done) {
        if (lsquic_stream_shutdown(stream, 1) != 0 &&
            errno != EBADF && errno != EAGAIN && errno != EWOULDBLOCK) {
            driver_endpoint_fail(endpoint, "shutdown_write:%s", strerror(errno));
            return;
        }
        ctx->write_done = true;
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_wantread(stream, 1);
    }
}

static void driver_endpoint_on_read(lsquic_stream_t *stream,
                                    lsquic_stream_ctx_t *stream_ctx) {
    driver_stream_ctx_t *ctx = (driver_stream_ctx_t *)stream_ctx;
    if (ctx == NULL) {
        return;
    }
    driver_endpoint_t *endpoint = ctx->endpoint;
    driver_request_node_t *node = ctx->request;
    driver_resp_t *resp = node->resp;

    driver_drain_hsets(stream);

    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0) {
            if (resp != NULL &&
                driver_buf_append(&resp->body, buf, (size_t)nread) != 0) {
                driver_endpoint_fail(endpoint, "out_of_memory");
                return;
            }
            continue;
        }
        if (nread == 0) {
            ctx->read_done = true;
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_shutdown(stream, 0);
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Wait for the next readable event. Flow-control credit was
            // released by the reads above, so the server can make progress.
            return;
        }
        if (errno == ECONNRESET || errno == EBADF) {
            if (resp != NULL) {
                resp->reset = true;
            }
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_close(stream);
            return;
        }
        driver_endpoint_fail(endpoint, "read_body:%s", strerror(errno));
        return;
    }
}

static void driver_endpoint_on_reset(lsquic_stream_t *stream,
                                     lsquic_stream_ctx_t *stream_ctx, int how) {
    (void)stream;
    driver_stream_ctx_t *ctx = (driver_stream_ctx_t *)stream_ctx;
    if (ctx == NULL) {
        return;
    }
    driver_request_node_t *node = ctx->request;
    if ((how == 0 || how == 2) && node->resp != NULL) {
        node->resp->reset = true;
    }
}

static void driver_endpoint_on_close(lsquic_stream_t *stream,
                                     lsquic_stream_ctx_t *stream_ctx) {
    (void)stream;
    driver_stream_ctx_t *ctx = (driver_stream_ctx_t *)stream_ctx;
    if (ctx == NULL) {
        return;
    }
    driver_request_node_t *node = ctx->request;
    node->stream = NULL;
    if (node->resp != NULL) {
        node->resp->done = true;
    }
    free(ctx);
}

static const struct lsquic_stream_if driver_endpoint_stream_callbacks = {
    .on_new_conn = driver_endpoint_on_new_conn,
    .on_conn_closed = driver_endpoint_on_conn_closed,
    .on_new_stream = driver_endpoint_on_new_stream,
    .on_read = driver_endpoint_on_read,
    .on_write = driver_endpoint_on_write,
    .on_close = driver_endpoint_on_close,
    .on_hsk_done = driver_endpoint_on_hsk_done,
    .on_reset = driver_endpoint_on_reset,
    .on_hset_in = driver_endpoint_on_hset_in,
    .on_conncloseframe_received = driver_endpoint_on_conncloseframe,
};

// hsi_create_header_set needs the stream context, so it is a function rather
// than a plain table entry above.
static void *driver_hset_create(void *hsi_ctx, lsquic_stream_t *stream,
                                int is_push_promise) {
    (void)hsi_ctx;
    (void)is_push_promise;
    driver_stream_ctx_t *ctx = (driver_stream_ctx_t *)lsquic_stream_get_ctx(stream);
    driver_resp_t *resp = ctx != NULL && ctx->request != NULL
                              ? ctx->request->resp
                              : NULL;
    return driver_hset_new(resp);
}

// ---------------------------------------------------------------------------
// Endpoint lifecycle
// ---------------------------------------------------------------------------

static int driver_socket_bind(int family, struct sockaddr_storage *local,
                              socklen_t *local_len) {
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(local, 0, sizeof(*local));
    if (family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)local;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_ANY);
        addr->sin_port = 0;
        *local_len = sizeof(*addr);
    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)local;
        addr->sin6_family = AF_INET6;
        addr->sin6_addr = in6addr_any;
        addr->sin6_port = 0;
        *local_len = sizeof(*addr);
    }

    if (bind(sock, (struct sockaddr *)local, *local_len) != 0) {
        close(sock);
        return -1;
    }
    if (getsockname(sock, (struct sockaddr *)local, local_len) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

driver_endpoint_conn_result_t driver_endpoint_connect(const char *base_url) {
    driver_endpoint_conn_result_t result = {
        .inner = driver_result_ok(),
        .endpoint = NULL,
    };

    static bool global_initialized;
    if (!global_initialized) {
        if (getenv("LSQUIC_DEBUG") != NULL) {
            lsquic_logger_init(&driver_logger_if, NULL, LLTS_NONE);
            lsquic_set_log_level("debug");
        }
        if (lsquic_global_init(LSQUIC_GLOBAL_CLIENT) != 0) {
            driver_result_set_error(&result.inner, "lsquic_global_init");
            return result;
        }
        global_initialized = true;
    }

    const char *without_scheme = strstr(base_url, "://");
    without_scheme = without_scheme == NULL ? base_url : without_scheme + 3;

    const char *colon = strrchr(without_scheme, ':');
    if (colon == NULL || colon == without_scheme) {
        driver_result_set_error(&result.inner, "base_url_missing_port");
        return result;
    }
    size_t host_len = (size_t)(colon - without_scheme);
    unsigned long port = strtoul(colon + 1, NULL, 10);
    if (port == 0 || port > 65535) {
        driver_result_set_error(&result.inner, "base_url_bad_port");
        return result;
    }

    char *host = malloc(host_len + 1);
    if (host == NULL) {
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }
    memcpy(host, without_scheme, host_len);
    host[host_len] = '\0';

    char service[6];
    snprintf(service, sizeof(service), "%lu", port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *resolved = NULL;
    if (getaddrinfo(host, service, &hints, &resolved) != 0 ||
        resolved == NULL) {
        free(host);
        driver_result_set_error(&result.inner, "resolve_failed");
        return result;
    }

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    int sock = driver_socket_bind(resolved->ai_family, &local, &local_len);
    if (sock < 0) {
        freeaddrinfo(resolved);
        free(host);
        driver_result_set_error(&result.inner, "bind:%s", strerror(errno));
        return result;
    }

    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(&peer, resolved->ai_addr, resolved->ai_addrlen);
    socklen_t peer_len = (socklen_t)resolved->ai_addrlen;
    freeaddrinfo(resolved);

    driver_endpoint_t *endpoint = calloc(1, sizeof(*endpoint));
    if (endpoint == NULL) {
        close(sock);
        free(host);
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }
    endpoint->sock = sock;
    endpoint->host = host;
    endpoint->local = local;
    endpoint->local_len = local_len;
    endpoint->peer = peer;
    endpoint->peer_len = peer_len;
    endpoint->next_id = 1;

    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    settings.es_handshake_to = HANDSHAKE_DEADLINE_MS * 1000ULL;
    settings.es_idle_timeout = 30;
    settings.es_init_max_data = 10000000;
    settings.es_init_max_stream_data_bidi_local = 1000000;
    settings.es_init_max_stream_data_bidi_remote = 1000000;
    settings.es_init_max_stream_data_uni = 1000000;
    settings.es_init_max_streams_bidi = 100;
    settings.es_init_max_streams_uni = 100;
    settings.es_allow_migration = 0;

    // lsquic stores this pointer for the lifetime of the engine rather than
    // copying it, so it must have static storage duration.
    static const struct lsquic_hset_if hsi_if = {
        .hsi_create_header_set = driver_hset_create,
        .hsi_prepare_decode = driver_hsi_prepare_decode,
        .hsi_process_header = driver_hsi_process_header,
        .hsi_discard_header_set = driver_hset_free,
    };

    struct lsquic_engine_api engine_api = {
        .ea_settings = &settings,
        .ea_stream_if = &driver_endpoint_stream_callbacks,
        .ea_stream_if_ctx = endpoint,
        .ea_packets_out = driver_packets_out,
        .ea_packets_out_ctx = endpoint,
        .ea_get_ssl_ctx = driver_get_ssl_ctx,
        .ea_hsi_if = &hsi_if,
        .ea_hsi_ctx = endpoint,
    };

    endpoint->engine = lsquic_engine_new(LSENG_HTTP, &engine_api);
    if (endpoint->engine == NULL) {
        close(sock);
        free(host);
        free(endpoint);
        driver_result_set_error(&result.inner, "lsquic_engine_new");
        return result;
    }

    endpoint->conn = lsquic_engine_connect(
        endpoint->engine, N_LSQVER, (struct sockaddr *)&endpoint->local,
        (struct sockaddr *)&endpoint->peer, endpoint,
        (lsquic_conn_ctx_t *)endpoint, endpoint->host, 0, NULL, 0, NULL, 0);
    if (endpoint->conn == NULL) {
        lsquic_engine_destroy(endpoint->engine);
        close(sock);
        free(host);
        free(endpoint);
        driver_result_set_error(&result.inner, "lsquic_engine_connect");
        return result;
    }

    uint64_t deadline = driver_now_ms() + HANDSHAKE_DEADLINE_MS;
    while (!endpoint->handshake_done && !endpoint->handshake_failed &&
           !endpoint->conn_closed && driver_now_ms() < deadline) {
        driver_result_t iter = driver_endpoint_iterate(endpoint, deadline);
        if (iter.error != NULL) {
            driver_result_free(&iter);
            break;
        }
    }

    if (!endpoint->handshake_done) {
        const char *reason = endpoint->error != NULL
                                 ? endpoint->error
                                 : endpoint->conn_closed
                                       ? "handshake_closed"
                                       : endpoint->handshake_failed
                                             ? "handshake_failed"
                                             : "handshake_timeout";
        driver_result_set_error(&result.inner, "%s", reason);
        driver_endpoint_shutdown(endpoint);
        return result;
    }

    // Give the server's control stream and SETTINGS a chance to arrive before
    // the first request. Request streams may legally precede them, but some
    // servers only establish their HTTP/3 state after processing SETTINGS.
    uint64_t settle_deadline = driver_now_ms() + 100;
    while (!endpoint->conn_closed && driver_now_ms() < settle_deadline) {
        driver_result_t iter = driver_endpoint_iterate(endpoint, settle_deadline);
        if (iter.error != NULL) {
            driver_result_free(&iter);
            break;
        }
    }
    if (endpoint->conn_closed) {
        driver_result_set_error(&result.inner, "%s",
                                endpoint->error != NULL ? endpoint->error
                                                        : "connection_closed");
        driver_endpoint_shutdown(endpoint);
        return result;
    }

    result.endpoint = endpoint;
    return result;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

static driver_request_node_t *driver_endpoint_find(driver_endpoint_t *endpoint,
                                                    uint64_t id) {
    for (driver_request_node_t *node = endpoint->requests; node != NULL;
         node = node->next) {
        if (node->id == id) {
            return node;
        }
    }
    return NULL;
}

driver_endpoint_req_result_t driver_endpoint_send_request(
    driver_endpoint_t *endpoint,
    driver_resps_t *resps,
    const char *method,
    const char *authority,
    const char *path,

    const unsigned char *body,
    size_t body_len,

    const driver_endpoint_req_header_t *extra,
    size_t extra_count,

    const driver_endpoint_req_header_t *trailers,
    size_t trailers_count) {
    driver_endpoint_req_result_t result = {
        .inner = driver_result_ok(),
        .id = 0,
    };

    if (endpoint == NULL || endpoint->conn == NULL || endpoint->conn_closed) {
        driver_result_set_error(&result.inner, "connection_closed");
        return result;
    }

    driver_request_node_t *node = calloc(1, sizeof(*node));
    driver_resp_t *resp = calloc(1, sizeof(*resp));
    if (node == NULL || resp == NULL) {
        free(node);
        free(resp);
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }

    node->id = endpoint->next_id++;
    node->resp = resp;
    node->request.headers = DRIVER_HEADER_LIST_NULL;
    node->request.trailers = DRIVER_HEADER_LIST_NULL;

    size_t header_count = 5 + extra_count;
    driver_kv_t *kvs = calloc(header_count, sizeof(*kvs));
    if (kvs == NULL) {
        free(node);
        free(resp);
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }
    kvs[0] = (driver_kv_t){":method", method};
    kvs[1] = (driver_kv_t){":scheme", "https"};
    kvs[2] = (driver_kv_t){":authority", authority};
    kvs[3] = (driver_kv_t){":path", path};
    kvs[4] = (driver_kv_t){"user-agent", "lsquic"};
    for (size_t i = 0; i < extra_count; i++) {
        kvs[5 + i] = (driver_kv_t){extra[i].name, extra[i].value};
    }
    int build_rc = driver_header_list_build(&node->request.headers, kvs,
                                            header_count);
    free(kvs);
    if (build_rc != 0) {
        free(node);
        free(resp);
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }

    if (trailers_count > 0) {
        driver_kv_t *trailer_kvs = calloc(trailers_count, sizeof(*trailer_kvs));
        if (trailer_kvs == NULL) {
            driver_header_list_free(&node->request.headers);
            free(node);
            free(resp);
            driver_result_set_error(&result.inner, "out_of_memory");
            return result;
        }
        for (size_t i = 0; i < trailers_count; i++) {
            trailer_kvs[i] = (driver_kv_t){trailers[i].name, trailers[i].value};
        }
        build_rc = driver_header_list_build(&node->request.trailers, trailer_kvs,
                                            trailers_count);
        free(trailer_kvs);
        if (build_rc != 0) {
            driver_header_list_free(&node->request.headers);
            free(node);
            free(resp);
            driver_result_set_error(&result.inner, "out_of_memory");
            return result;
        }
    }

    if (body_len > 0) {
        node->request.body = malloc(body_len);
        if (node->request.body == NULL) {
            driver_header_list_free(&node->request.headers);
            driver_header_list_free(&node->request.trailers);
            free(node);
            free(resp);
            driver_result_set_error(&result.inner, "out_of_memory");
            return result;
        }
        memcpy(node->request.body, body, body_len);
        node->request.body_len = body_len;
    }

    if (driver_resps_insert(resps, node->id, resp) != 0) {
        driver_header_list_free(&node->request.headers);
        driver_header_list_free(&node->request.trailers);
        free(node->request.body);
        free(node);
        free(resp);
        driver_result_set_error(&result.inner, "out_of_memory");
        return result;
    }

    // Append to the endpoint's request list *before* asking lsquic for a
    // stream: with a completed handshake, on_new_stream is called synchronously.
    driver_request_node_t **tail = &endpoint->requests;
    while (*tail != NULL) {
        tail = &(*tail)->next;
    }
    *tail = node;

    lsquic_conn_make_stream(endpoint->conn);

    result.id = node->id;
    return result;
}

driver_result_t driver_endpoint_flush(driver_endpoint_t *endpoint) {
    if (endpoint == NULL || endpoint->engine == NULL) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "not_connected");
        return result;
    }
    lsquic_engine_process_conns(endpoint->engine);
    if (lsquic_engine_has_unsent_packets(endpoint->engine)) {
        lsquic_engine_send_unsent_packets(endpoint->engine);
    }
    return driver_endpoint_result(endpoint);
}

driver_result_t driver_endpoint_iterate(driver_endpoint_t *endpoint,
                                        uint64_t deadline_ms) {
    if (endpoint == NULL || endpoint->engine == NULL) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "not_connected");
        return result;
    }
    if (endpoint->error != NULL) {
        return driver_endpoint_result(endpoint);
    }
    if (endpoint->conn_closed) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "connection_closed");
        return result;
    }

    lsquic_engine_process_conns(endpoint->engine);
    if (lsquic_engine_has_unsent_packets(endpoint->engine)) {
        lsquic_engine_send_unsent_packets(endpoint->engine);
    }
    if (endpoint->error != NULL) {
        return driver_endpoint_result(endpoint);
    }
    if (endpoint->conn_closed) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "connection_closed");
        return result;
    }
    if (endpoint->handshake_failed) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "handshake_failed");
        return result;
    }

    uint64_t now = driver_now_ms();
    if (now >= deadline_ms) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "scenario_timeout");
        return result;
    }

    uint64_t wait_ms = deadline_ms - now;
    if (wait_ms > MAX_POLL_WAIT_MS) {
        wait_ms = MAX_POLL_WAIT_MS;
    }
    int diff_us = 0;
    if (lsquic_engine_earliest_adv_tick(endpoint->engine, &diff_us)) {
        uint64_t tick_ms =
            diff_us < 0 ? 0 : (uint64_t)diff_us / 1000U;
        if (tick_ms < wait_ms) {
            wait_ms = tick_ms;
        }
    }

    struct pollfd pfd = {
        .fd = endpoint->sock,
        .events = POLLIN,
        .revents = 0,
    };
    int poll_rc = poll(&pfd, 1, (int)wait_ms);
    if (poll_rc < 0) {
        if (errno == EINTR) {
            return driver_result_ok();
        }
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "poll:%s", strerror(errno));
        return result;
    }
    if (poll_rc > 0 && (pfd.revents & POLLIN)) {
        unsigned char buf[65535];
        struct sockaddr_storage source;
        socklen_t source_len = sizeof(source);
        ssize_t nread = recvfrom(endpoint->sock, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&source, &source_len);
        if (nread > 0) {
            (void)lsquic_engine_packet_in(
                endpoint->engine, buf, (size_t)nread,
                (struct sockaddr *)&endpoint->local,
                (struct sockaddr *)&source, endpoint, 0);
            lsquic_engine_process_conns(endpoint->engine);
            if (lsquic_engine_has_unsent_packets(endpoint->engine)) {
                lsquic_engine_send_unsent_packets(endpoint->engine);
            }
        }
    } else {
        // A timer expired: process_conns() is what advances loss detection,
        // pacing, and the idle timeout.
        lsquic_engine_process_conns(endpoint->engine);
        if (lsquic_engine_has_unsent_packets(endpoint->engine)) {
            lsquic_engine_send_unsent_packets(endpoint->engine);
        }
    }

    if (endpoint->error != NULL) {
        return driver_endpoint_result(endpoint);
    }
    if (endpoint->conn_closed) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "connection_closed");
        return result;
    }
    return driver_result_ok();
}

driver_result_t driver_endpoint_drive(driver_endpoint_t *endpoint,
                                      driver_resps_t *resps,
                                      uint64_t deadline_ms) {
    for (;;) {
        if (driver_resps_all_done(resps)) {
            return driver_result_ok();
        }
        if (endpoint->conn_closed) {
            driver_result_t result = driver_result_ok();
            driver_result_set_error(&result, "connection_closed");
            return result;
        }
        if (driver_now_ms() >= deadline_ms) {
            driver_result_t result = driver_result_ok();
            driver_result_set_error(&result, "scenario_timeout");
            return result;
        }
        driver_result_t result = driver_endpoint_iterate(endpoint, deadline_ms);
        if (result.error != NULL) {
            return result;
        }
    }
}

driver_result_t driver_endpoint_abort(driver_endpoint_t *endpoint, uint64_t id) {
    if (endpoint == NULL) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "not_connected");
        return result;
    }
    driver_request_node_t *node = driver_endpoint_find(endpoint, id);
    if (node == NULL) {
        driver_result_t result = driver_result_ok();
        driver_result_set_error(&result, "unknown_request");
        return result;
    }

    // The caller has already detached the response from its map. Stop
    // callbacks from touching it while the stream winds down.
    node->resp = NULL;
    if (node->stream != NULL) {
        // Closing a stream whose response direction is still open emits
        // STOP_SENDING (H3_REQUEST_CANCELLED is the app-level alternative).
        (void)lsquic_stream_close(node->stream);
    }
    return driver_endpoint_flush(endpoint);
}

bool driver_endpoint_is_closed(const driver_endpoint_t *endpoint) {
    return endpoint == NULL || endpoint->conn_closed;
}

driver_result_t driver_endpoint_close_gracefully(driver_endpoint_t *endpoint) {
    if (endpoint == NULL) {
        return driver_result_ok();
    }
    if (endpoint->conn != NULL && !endpoint->conn_closed) {
        lsquic_conn_close(endpoint->conn);
    }
    if (endpoint->engine != NULL) {
        lsquic_engine_process_conns(endpoint->engine);
        if (lsquic_engine_has_unsent_packets(endpoint->engine)) {
            lsquic_engine_send_unsent_packets(endpoint->engine);
        }
    }
    return driver_result_ok();
}

static void driver_request_node_free(driver_request_node_t *node) {
    if (node == NULL) {
        return;
    }
    driver_header_list_free(&node->request.headers);
    driver_header_list_free(&node->request.trailers);
    free(node->request.body);
    free(node);
}

void driver_endpoint_shutdown(driver_endpoint_t *endpoint) {
    if (endpoint == NULL) {
        return;
    }
    if (endpoint->engine != NULL) {
        lsquic_engine_destroy(endpoint->engine);
        endpoint->engine = NULL;
        endpoint->conn = NULL;
    }
    if (endpoint->sock >= 0) {
        close(endpoint->sock);
        endpoint->sock = -1;
    }
    driver_request_node_t *node = endpoint->requests;
    while (node != NULL) {
        driver_request_node_t *next = node->next;
        driver_request_node_free(node);
        node = next;
    }
    endpoint->requests = NULL;
    free(endpoint->host);
    free(endpoint->error);
    free(endpoint);
}
