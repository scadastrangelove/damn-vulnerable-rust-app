/* C shim for the DVR FFI tier.
 *
 * Models a minimal host (think an nginx/Pingora worker) that:
 *   1. calls back into Rust across the C ABI boundary, and
 *   2. hands Rust a request handle whose refcount the Rust module must manage.
 *
 * Educational only. Not for production.
 */

#include <stddef.h>
#include <stdint.h>

/* A stand-in for the host's per-request object. In nginx this is roughly the
 * `ngx_http_request_t` with its `->main->count` reference count. The host
 * expects the module to leave `count` balanced on every code path. */
typedef struct {
    int count;      /* reference count the module must decrement when done */
    int completed;  /* set by the host once count hits zero */
} host_request_t;

/* The Rust callback type: given a pointer+len buffer, return a status code.
 * Declared with the plain C ABI (no unwind). */
typedef int (*rust_body_cb)(const uint8_t *data, size_t len);

/* The host invokes the Rust body handler across the boundary. If the Rust
 * callback unwinds (panics) through this frame with a plain "C" ABI, behaviour
 * is undefined. This function exists to make that boundary real. */
int host_dispatch(rust_body_cb cb, const uint8_t *data, size_t len) {
    /* ... host bookkeeping would happen here ... */
    int rc = cb(data, len);
    /* ... and here, which is skipped entirely if cb unwound past us ... */
    return rc;
}

/* Increment the host request refcount before handing it to the module. */
void host_ref(host_request_t *r) {
    if (r) r->count += 1;
}

/* Called by the host after the module returns; if the module balanced the
 * count, the request completes, otherwise it leaks (stuck forever). */
void host_finish(host_request_t *r) {
    if (r && r->count == 0) {
        r->completed = 1;
    }
}
