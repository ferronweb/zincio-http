#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "endpoint.h"
#include "types.h"

// Harness-wide constants, mirroring scenario.rs. They are inputs to the
// requests this driver makes, not expectations: the harness still decides
// whether what came back is correct.
#define SMALL_LEN 1024
#define BIG_HEADER_LEN (32 * 1024)
#define LONG_URI_LEN (8 * 1024)
#define MANY_HEADERS 200
#define ABORT_AFTER (64 * 1024)

// Generous enough for the 1 MiB transfers on a loaded CI runner; the harness
// has its own (longer) timeout around the whole exec.
#define SCENARIO_DEADLINE_MS 100000

typedef struct {
    const char *method;
    const char *path;
    size_t upload_len;
    size_t count;
    uint64_t idle_ms;
} driver_params_t;

static void driver_emit(uint16_t status, size_t length, const char *digest,
                        bool trailers, bool hints, const char *err) {
    printf("status=%u len=%zu sha=", status, length);
    if (digest == NULL || digest[0] == '\0') {
        putchar('-');
    } else {
        fputs(digest, stdout);
    }
    printf(" trailers=%d hints=%d err=%s\n", trailers ? 1 : 0, hints ? 1 : 0,
           err == NULL ? "" : err);
}

static void driver_emit_failure(const char *err) {
    // Spaces would break the observation line format.
    size_t len = strlen(err);
    char *normalized = malloc(len + 1);
    if (normalized == NULL) {
        driver_emit(0, 0, "", false, false, "out_of_memory");
        return;
    }
    memcpy(normalized, err, len + 1);
    for (char *p = normalized; *p != '\0'; p++) {
        if (*p == ' ') {
            *p = '_';
        }
    }
    driver_emit(0, 0, "", false, false, normalized);
    free(normalized);
}

static void driver_emit_result(driver_result_t *result) {
    driver_emit_failure(result->error != NULL ? result->error : "unknown_error");
    driver_result_free(result);
}

static void pattern_fill(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] = "ABCD"[i % 4];
    }
}

static void sha256_hex(const unsigned char *data, size_t len, char out[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    }
    out[64] = '\0';
}

static void observe(uint64_t id, const driver_resps_t *resps) {
    driver_resp_t *resp = driver_resps_get(resps, id);
    if (resp == NULL) {
        driver_emit_failure("no_observation");
        return;
    }
    if (resp->reset) {
        driver_emit_failure("request_reset");
        return;
    }
    if (resp->status == 0) {
        driver_emit_failure("no_response");
        return;
    }

    char digest[65] = "";
    if (resp->body.len > 0) {
        sha256_hex(resp->body.data, resp->body.len, digest);
    }
    driver_emit(resp->status, resp->body.len, digest, resp->trailers, resp->hints,
                "");
}

static const char *authority_of(const char *base_url) {
    const char *scheme = strstr(base_url, "://");
    return scheme == NULL ? base_url : scheme + 3;
}

typedef struct {
    driver_endpoint_req_header_t *items;
    size_t count;
    char **names;
    size_t names_count;
    char *big_value;
    char *long_path;
    unsigned char *body;
    driver_endpoint_req_header_t trailers[1];
    size_t trailer_count;
} driver_request_builder_t;

static void request_builder_free(driver_request_builder_t *builder) {
    for (size_t i = 0; i < builder->names_count; i++) {
        free(builder->names[i]);
    }
    free(builder->names);
    free(builder->big_value);
    free(builder->long_path);
    free(builder->body);
    free(builder->items);
    builder->names = NULL;
    builder->items = NULL;
}

static int request_builder_prepare(driver_request_builder_t *builder,
                                   const char *scenario, const char *path,
                                   size_t upload_len) {
    memset(builder, 0, sizeof(*builder));
    builder->items = calloc(MANY_HEADERS + 1, sizeof(*builder->items));
    if (builder->items == NULL) {
        return -1;
    }

    if (strcmp(scenario, "many_headers") == 0) {
        builder->names = calloc(MANY_HEADERS, sizeof(*builder->names));
        if (builder->names == NULL) {
            return -1;
        }
        for (size_t i = 0; i < MANY_HEADERS; i++) {
            builder->names[i] = malloc(32);
            if (builder->names[i] == NULL) {
                builder->names_count = i;
                return -1;
            }
            snprintf(builder->names[i], 32, "x-interop-%04zu", i);
            builder->names_count = i + 1;
            builder->items[builder->count++] =
                (driver_endpoint_req_header_t){builder->names[i], "v"};
        }
    } else if (strcmp(scenario, "big_header_rejected") == 0) {
        builder->big_value = malloc(BIG_HEADER_LEN + 1);
        if (builder->big_value == NULL) {
            return -1;
        }
        memset(builder->big_value, 'v', BIG_HEADER_LEN);
        builder->big_value[BIG_HEADER_LEN] = '\0';
        builder->items[builder->count++] =
            (driver_endpoint_req_header_t){"x-big", builder->big_value};
    } else if (strcmp(scenario, "expect_continue") == 0) {
        builder->items[builder->count++] =
            (driver_endpoint_req_header_t){"expect", "100-continue"};
    }

    if (strcmp(scenario, "long_uri") == 0) {
        size_t path_len = strlen(path);
        builder->long_path = malloc(path_len + 1 + LONG_URI_LEN + 1);
        if (builder->long_path == NULL) {
            return -1;
        }
        memcpy(builder->long_path, path, path_len);
        builder->long_path[path_len] = '?';
        pattern_fill((unsigned char *)builder->long_path + path_len + 1,
                     LONG_URI_LEN);
        builder->long_path[path_len + 1 + LONG_URI_LEN] = '\0';
    }

    if (upload_len > 0) {
        builder->body = malloc(upload_len);
        if (builder->body == NULL) {
            return -1;
        }
        pattern_fill(builder->body, upload_len);
    }

    if (strcmp(scenario, "trailers") == 0) {
        builder->trailers[0] =
            (driver_endpoint_req_header_t){"x-interop-req", "1"};
        builder->trailer_count = 1;
    }

    return 0;
}

static void run_generic(const char *base_url, const char *scenario,
                        const char *method, const char *path,
                        size_t upload_len) {
    uint64_t deadline = driver_now_ms() + SCENARIO_DEADLINE_MS;
    const char *authority = authority_of(base_url);

    driver_request_builder_t builder;
    if (request_builder_prepare(&builder, scenario, path, upload_len) != 0) {
        request_builder_free(&builder);
        driver_emit_failure("out_of_memory");
        return;
    }

    const char *request_path =
        builder.long_path != NULL ? builder.long_path : path;

    driver_endpoint_conn_result_t connected = driver_endpoint_connect(base_url);
    if (connected.inner.error != NULL) {
        request_builder_free(&builder);
        driver_emit_result(&connected.inner);
        return;
    }
    driver_endpoint_t *endpoint = connected.endpoint;
    driver_resps_t resps = DRIVER_RESPS_NULL;

    driver_endpoint_req_result_t sent = driver_endpoint_send_request(
        endpoint, &resps, method, authority, request_path, builder.body,
        upload_len, builder.items, builder.count, builder.trailers,
        builder.trailer_count);
    request_builder_free(&builder);

    if (sent.inner.error != NULL) {
        driver_emit_result(&sent.inner);
    } else {
        driver_result_t driven = driver_endpoint_drive(endpoint, &resps, deadline);
        if (driven.error != NULL) {
            driver_emit_result(&driven);
        } else {
            observe(sent.id, &resps);
        }
        driver_endpoint_close_gracefully(endpoint);
    }

    driver_endpoint_shutdown(endpoint);
    driver_resps_free(&resps);
}

static void run_concurrency(const char *base_url, const char *path,
                            size_t count) {
    uint64_t deadline = driver_now_ms() + SCENARIO_DEADLINE_MS;
    const char *authority = authority_of(base_url);

    driver_endpoint_conn_result_t connected = driver_endpoint_connect(base_url);
    if (connected.inner.error != NULL) {
        char *reason = connected.inner.error;
        for (size_t i = 0; i < count; i++) {
            driver_emit_failure(reason);
        }
        driver_result_free(&connected.inner);
        return;
    }
    driver_endpoint_t *endpoint = connected.endpoint;
    driver_resps_t resps = DRIVER_RESPS_NULL;

    uint64_t *ids = malloc(count * sizeof(*ids));
    if (ids == NULL) {
        for (size_t i = 0; i < count; i++) {
            driver_emit_failure("out_of_memory");
        }
        driver_endpoint_shutdown(endpoint);
        return;
    }

    size_t sent_count = 0;
    char *send_error = NULL;
    for (size_t i = 0; i < count; i++) {
        driver_endpoint_req_result_t sent = driver_endpoint_send_request(
            endpoint, &resps, "GET", authority, path, NULL, 0, NULL, 0, NULL, 0);
        if (sent.inner.error != NULL) {
            send_error = sent.inner.error;  // Keep the allocation; freed below.
            break;
        }
        ids[sent_count++] = sent.id;
    }

    bool drive_ok = false;
    char *drive_error = NULL;
    if (send_error == NULL) {
        driver_result_t driven = driver_endpoint_drive(endpoint, &resps, deadline);
        drive_ok = driven.error == NULL;
        if (!drive_ok) {
            drive_error = driven.error;
        }
    }

    if (drive_ok) {
        for (size_t i = 0; i < sent_count; i++) {
            observe(ids[i], &resps);
        }
    } else {
        const char *reason = send_error != NULL
                                 ? send_error
                                 : drive_error != NULL ? drive_error
                                                       : "unknown_error";
        for (size_t i = 0; i < count; i++) {
            driver_emit_failure(reason);
        }
    }

    free(ids);
    free(send_error);
    free(drive_error);
    driver_endpoint_close_gracefully(endpoint);
    driver_endpoint_shutdown(endpoint);
    driver_resps_free(&resps);
}

static void run_abort(const char *base_url, const char *path) {
    uint64_t deadline = driver_now_ms() + SCENARIO_DEADLINE_MS;
    const char *authority = authority_of(base_url);

    driver_endpoint_conn_result_t connected = driver_endpoint_connect(base_url);
    if (connected.inner.error != NULL) {
        driver_emit_result(&connected.inner);
        return;
    }
    driver_endpoint_t *endpoint = connected.endpoint;
    driver_resps_t resps = DRIVER_RESPS_NULL;

    driver_endpoint_req_result_t sent = driver_endpoint_send_request(
        endpoint, &resps, "GET", authority, path, NULL, 0, NULL, 0, NULL, 0);
    if (sent.inner.error != NULL) {
        driver_emit_result(&sent.inner);
        driver_endpoint_shutdown(endpoint);
        driver_resps_free(&resps);
        return;
    }

    // Read a bounded prefix, then cancel the stream.
    for (;;) {
        driver_resp_t *resp = driver_resps_get(&resps, sent.id);
        if (resp != NULL && (resp->body.len >= ABORT_AFTER || resp->done)) {
            break;
        }
        if (driver_now_ms() >= deadline) {
            driver_emit_failure("scenario_timeout");
            driver_endpoint_shutdown(endpoint);
            driver_resps_free(&resps);
            return;
        }
        driver_result_t iter = driver_endpoint_iterate(endpoint, deadline);
        if (iter.error != NULL) {
            driver_emit_result(&iter);
            driver_endpoint_shutdown(endpoint);
            driver_resps_free(&resps);
            return;
        }
    }

    driver_resp_t *aborted = driver_resps_delete(&resps, sent.id);
    driver_result_t abort_result = driver_endpoint_abort(endpoint, sent.id);
    if (aborted != NULL) {
        driver_resp_free(aborted);
        free(aborted);
    }
    if (abort_result.error != NULL) {
        driver_emit_result(&abort_result);
        driver_endpoint_shutdown(endpoint);
        driver_resps_free(&resps);
        return;
    }

    // The connection must still serve a fresh request.
    driver_endpoint_req_result_t follow = driver_endpoint_send_request(
        endpoint, &resps, "GET", authority, "/small", NULL, 0, NULL, 0, NULL, 0);
    if (follow.inner.error != NULL) {
        driver_emit_result(&follow.inner);
    } else {
        driver_result_t driven = driver_endpoint_drive(endpoint, &resps, deadline);
        if (driven.error != NULL) {
            driver_emit_result(&driven);
        } else {
            observe(follow.id, &resps);
        }
        driver_endpoint_close_gracefully(endpoint);
    }

    driver_endpoint_shutdown(endpoint);
    driver_resps_free(&resps);
}

static void run_idle(const char *base_url, const char *method, const char *path,
                     uint64_t idle_ms) {
    uint64_t deadline = driver_now_ms() + SCENARIO_DEADLINE_MS;
    const char *authority = authority_of(base_url);

    driver_endpoint_conn_result_t connected = driver_endpoint_connect(base_url);
    if (connected.inner.error != NULL) {
        driver_emit_result(&connected.inner);
        return;
    }
    driver_endpoint_t *endpoint = connected.endpoint;

    usleep((useconds_t)(idle_ms * 1000));

    // The H3 server reaps idle connections. Process whatever arrived while we
    // slept so a closed connection is noticed before trying to reuse it.
    uint64_t grace_deadline = driver_now_ms() + 200;
    while (driver_now_ms() < grace_deadline) {
        driver_result_t iter = driver_endpoint_iterate(endpoint, grace_deadline);
        if (iter.error != NULL) {
            driver_result_free(&iter);
            break;
        }
    }

    bool reused = false;
    driver_resps_t resps = DRIVER_RESPS_NULL;
    if (!driver_endpoint_is_closed(endpoint)) {
        driver_endpoint_req_result_t sent = driver_endpoint_send_request(
            endpoint, &resps, method, authority, path, NULL, 0, NULL, 0, NULL, 0);
        if (sent.inner.error == NULL) {
            driver_result_t driven =
                driver_endpoint_drive(endpoint, &resps, deadline);
            if (driven.error == NULL) {
                observe(sent.id, &resps);
                reused = true;
            } else {
                driver_result_free(&driven);
            }
        } else {
            driver_result_free(&sent.inner);
        }
    }

    driver_endpoint_close_gracefully(endpoint);
    driver_endpoint_shutdown(endpoint);
    driver_resps_free(&resps);
    if (reused) {
        return;
    }

    // The idle connection was reaped. Reconnecting is the correct client
    // behaviour, and "reconnectable" is what the scenario asserts.
    connected = driver_endpoint_connect(base_url);
    if (connected.inner.error != NULL) {
        driver_emit_result(&connected.inner);
        return;
    }
    endpoint = connected.endpoint;
    resps = DRIVER_RESPS_NULL;

    driver_endpoint_req_result_t sent = driver_endpoint_send_request(
        endpoint, &resps, method, authority, path, NULL, 0, NULL, 0, NULL, 0);
    if (sent.inner.error != NULL) {
        driver_emit_result(&sent.inner);
    } else {
        driver_result_t driven = driver_endpoint_drive(endpoint, &resps, deadline);
        if (driven.error != NULL) {
            driver_emit_result(&driven);
        } else {
            observe(sent.id, &resps);
        }
        driver_endpoint_close_gracefully(endpoint);
    }
    driver_endpoint_shutdown(endpoint);
    driver_resps_free(&resps);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // Idle mode: the container's main process. Announce readiness for the
        // harness, then sleep; scenarios arrive via exec.
        printf("interop-driver ready\n");
        fflush(stdout);
        for (;;) {
            sleep(3600);
        }
    }
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        return 0;
    }
    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s <base_url> <protocol> <scenario> [key=value...]\n",
                argv[0]);
        return 2;
    }

    const char *base_url = argv[1];
    const char *protocol = argv[2];
    const char *scenario = argv[3];

    if (strcmp(protocol, "h3") != 0) {
        fprintf(stderr, "lsquic-driver: lsquic speaks only HTTP/3, got %s\n",
                protocol);
        return 2;
    }

    driver_params_t params = {
        .method = "GET",
        .path = "/small",
        .upload_len = 0,
        .count = 32,
        .idle_ms = 3000,
    };
    for (int i = 4; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq == NULL) {
            fprintf(stderr, "lsquic-driver: invalid key-value pair: %s\n",
                    argv[i]);
            return 2;
        }
        *eq = '\0';
        const char *key = argv[i];
        const char *value = eq + 1;
        if (strcmp(key, "method") == 0) {
            params.method = value;
        } else if (strcmp(key, "path") == 0) {
            params.path = value;
        } else if (strcmp(key, "upload_len") == 0) {
            params.upload_len = (size_t)strtoull(value, NULL, 10);
        } else if (strcmp(key, "count") == 0) {
            params.count = (size_t)strtoull(value, NULL, 10);
        } else if (strcmp(key, "idle_ms") == 0) {
            params.idle_ms = strtoull(value, NULL, 10);
        }
    }

    if (strcmp(scenario, "concurrency") == 0) {
        run_concurrency(base_url, params.path, params.count);
    } else if (strcmp(scenario, "abort_midstream") == 0) {
        run_abort(base_url, params.path);
    } else if (strcmp(scenario, "idle_reuse") == 0) {
        run_idle(base_url, params.method, params.path, params.idle_ms);
    } else {
        run_generic(base_url, scenario, params.method, params.path,
                    params.upload_len);
    }

    fflush(stdout);
    return 0;
}
