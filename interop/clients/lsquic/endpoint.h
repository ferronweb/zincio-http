#ifndef DRIVER_ENDPOINT_H
#define DRIVER_ENDPOINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "types.h"

// Growable byte buffer used for response bodies.
typedef struct {
    unsigned char *data;
    size_t len;
    size_t capacity;
} driver_buf_t;

#define DRIVER_BUF_NULL ((driver_buf_t){NULL, 0, 0})
#define DRIVER_BUF_INIT_MALLOCED(data, len) ((driver_buf_t){data, len, len})
#define DRIVER_BUF_INIT_MALLOCED_EX(data, len, capacity) \
    ((driver_buf_t){(data), (len), (capacity)})

int driver_buf_append(driver_buf_t *buf, const void *data, size_t len);
void driver_buf_free(driver_buf_t *buf);

// What one request stream produced, as far as the client can observe it.
typedef struct {
    uint16_t status;
    driver_buf_t body;
    bool trailers;
    bool hints;
    bool done;
    bool reset;
} driver_resp_t;

void driver_resp_free(driver_resp_t *resp);

// Response map keyed by request id. The tree owns the driver_resp_t pointers
// it holds; driver_resps_delete() detaches one and returns it to the caller.
typedef struct driver_resps_node_t {
    uint64_t id;
    driver_resp_t *resp;
    struct driver_resps_node_t *left;
    struct driver_resps_node_t *right;
} driver_resps_node_t;

typedef struct {
    driver_resps_node_t *root;
} driver_resps_t;

#define DRIVER_RESPS_NULL ((driver_resps_t){NULL})

int driver_resps_insert(driver_resps_t *resps, uint64_t id, driver_resp_t *resp);
driver_resp_t *driver_resps_delete(driver_resps_t *resps, uint64_t id);
driver_resp_t *driver_resps_get(const driver_resps_t *resps, uint64_t id);
void driver_resps_free(driver_resps_t *resps);

typedef struct driver_endpoint driver_endpoint_t;

typedef struct {
    driver_result_t inner;
    driver_endpoint_t *endpoint;
} driver_endpoint_conn_result_t;

typedef struct {
    const char *name;
    const char *value;
} driver_endpoint_req_header_t;

typedef struct {
    driver_result_t inner;
    uint64_t id;
} driver_endpoint_req_result_t;

// Connects and completes the QUIC/TLS handshake.
driver_endpoint_conn_result_t driver_endpoint_connect(const char *base_url);

// Starts one request stream. The request and response state is owned by the
// endpoint; `id` identifies it in the `driver_resps_t` passed to drive().
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
    size_t trailers_count);

// Sends any packets currently queued in the engine.
driver_result_t driver_endpoint_flush(driver_endpoint_t *endpoint);

// One event-loop iteration. The deadline is an absolute CLOCK_MONOTONIC time in
// milliseconds (see driver_now_ms()).
driver_result_t driver_endpoint_iterate(driver_endpoint_t *endpoint,
                                        uint64_t deadline_ms);

// Pumps the connection until every response in `resps` is done, the connection
// fails, or the deadline expires.
driver_result_t driver_endpoint_drive(driver_endpoint_t *endpoint,
                                      driver_resps_t *resps,
                                      uint64_t deadline_ms);

// Cancels a stream, which sends STOP_SENDING for the response direction.
driver_result_t driver_endpoint_abort(driver_endpoint_t *endpoint, uint64_t id);

// True once the QUIC connection is closed (by either peer or an error).
bool driver_endpoint_is_closed(const driver_endpoint_t *endpoint);

// Closes the QUIC connection politely. Best-effort: observations are already
// collected by the time this runs.
driver_result_t driver_endpoint_close_gracefully(driver_endpoint_t *endpoint);

// Destroys the engine, closes the socket, and frees all request state.
void driver_endpoint_shutdown(driver_endpoint_t *endpoint);

// Absolute monotonic clock in milliseconds, shared by the endpoint and main().
uint64_t driver_now_ms(void);

// Frees a dynamically-allocated error string.
void driver_result_free(driver_result_t *result);

#endif
