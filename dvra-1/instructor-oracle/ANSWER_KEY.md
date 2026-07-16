# ANSWER KEY — spoilers

Do not read until you have reviewed the target. This is the graded truth for the
eleven planted issues. Section references are to *Rust Security Code Review —
Canonical Best Practices*. Line numbers match the as-shipped source.

Legend: **R** reachable-real · **D** decoy-unreachable · **F** fuzz-only ·
**T** threat-model-dependent.

---

## DVR-01 — SQL injection · **R** · CWE-89 · `user_search.rs:11`

The username is interpolated into the query string with `format!`. `db.rs`'s
interpreter treats `' OR '1'='1` as a tautology, so it returns every user.

- **Trigger:** `GET /users/search?username=' OR '1'='1`
- **Reachable:** yes, from `PublicEdge`.
- **Fix:** never build query text from the value; filter/parameterize
  (`fixed_handle` filters in Rust; a real DB uses bound parameters). §5, §6
  (Raw vs Validated types).
- **Grade note:** static-visible. Everyone should get this one.

## DVR-02 — Path traversal · **R** · CWE-22 · `file_download.rs:17`

`base.join(client_name)` with no containment check. `../../etc/passwd` resolves
out of `upload_dir`; an actual `open()` follows it.

- **Trigger:** `GET /files/download?name=../../etc/passwd`
- **Fix:** `fixed_handle` rejects absolute/`..` and checks `starts_with(base)`.
  **This is intentionally still incomplete** — it does not defend against a
  symlink inside `upload_dir` or a TOCTOU race between the check and a later
  open. The robust fix is to never use the client name at all and store under a
  generated id (`upload::fixed_store`). Credit reviewers who flag that the
  "obvious" fix is not sufficient. §5.

## DVR-03 — Broken object-level authorization (IDOR) · **R** · CWE-639 · `documents.rs:17`

Document is fetched by id with no ownership check; any principal reads any
document. Note there is **no sink token** to grep for — this requires reasoning
about authorization, which is why SAST and junior reviewers miss it.

- **Trigger:** as `alice`, `GET /documents/get?id=11` (bob's doc).
- **Fix:** deny-by-default; require `owner == principal || is_admin`. Role is not
  per-object rights. §6.
- **Grade note:** the highest-value "did they think, not grep" signal.

## DVR-04 — UTF-8 char-boundary panic · **F** · CWE-248 · `header_parse.rs:17`

`&value[..16]` slices at a raw byte offset. If byte 16 lands inside a multi-byte
character, it panics → DoS on a shared process. No `unwrap`, no `unsafe`:
invisible to pattern triage; a fuzzer finds it in seconds.

- **Trigger:** header value = 15 ASCII bytes + a multi-byte char (e.g. `é`),
  then `GET /headers/echo?h=<that header>`. See the `#[should_panic]` test.
- **Fix:** slice on char boundaries — `chars().take(n)` / `get(..n)` /
  `is_char_boundary`. §3.1.

## DVR-05 — Length underflow · **F** · CWE-191 · `framing.rs:21`

`declared as usize - HEADER` underflows when `declared < 4`. Debug build:
subtract-overflow panic. **Release build: wraps to ~`usize::MAX`** — a quieter,
arguably worse bug (the code then treats a near-infinite payload length as
valid). Demonstrates why a debug-only test is not a DoS test, and why
release-profile arithmetic semantics matter.

- **Trigger:** body = `00 00 00 02` (declared = 2). See `#[should_panic]` test.
- **Fix:** `checked_sub` + validate `declared` against the actual frame length
  before any arithmetic. §3.3 (the `a < len - b` trap), §4 (checked casts).

## DVR-06 — Unbounded allocation / expansion · **R** · CWE-770 · `upload.rs:23`

`Vec::with_capacity(declared)` sized from `x-declared-size`, plus an `x-repeat`
expansion factor. An attacker declares a huge size or repeat and exhausts
memory. OOM/abort rather than a clean panic.

- **Trigger:** header `x-declared-size: 999999999999`, or `x-repeat:
  999999999` with a small body.
- **Fix:** cap both before touching memory (`fixed_handle`). §3.1.
- **Grade note:** `with_capacity(client_value)` is a recognizable pattern —
  static-visible, but reviewers often miss the second (expansion) sink.

## DVR-07 — Decoy: unsound `unsafe`, never routed · **D** · CWE-843 · `native.rs:24`

`as_u32_slice` is genuinely unsound (assumes 4-byte alignment on a `&[u8]` that
is aligned to 1, and drops the tail). It will dominate any `rg unsafe` triage.
**But `native::handle` is never wired into `App::handle`** — it is dead on the
attacker path.

- **Correct verdict:** not a reachable finding. Recommend deleting the dead
  code (or, if it must exist, fixing the alignment/tail and Miri-testing it).
  Flagging it "critical reachable" is the **false positive** this decoy exists
  to catch. §1 (reachability / prioritization), §2.
- **Twist for advanced reviewers:** wire it into the router and run
  `cargo +nightly miri test` — now it is real, and Miri catches what the
  compiler did not.

## DVR-08 — Decoy: unreachable `unwrap` · **D** · CWE-248 · `validation.rs:25`

`raw.parse::<u64>().unwrap()` greps as dangerous, but the preceding guards
(non-empty, all ASCII digits, length ≤ 19) guarantee a valid `u64`. The unwrap
cannot fire.

- **Correct verdict:** safe as written. Best practice is to keep the `//
  SAFETY (logical):` comment documenting the invariant, or switch to `?` for
  defense in depth — but it is **not a bug**. Flagging it as a panic risk is the
  false positive. §3.1 (unwrap allowed with a documented unreachability proof).
- **Grade note:** credit reviewers who verify the guards actually establish the
  invariant (e.g. that length ≤ 19 really bounds it below `u64::MAX` — 20 nines
  overflow, 19 nines do not).

## DVR-09 — Hook command from config · **T** · CWE-78 · `hooks.rs:33`

Runs the operator-configured `post_hook_command`. Under the stated threat model
(config is operator-only and static, no request data in it), this is intended
functionality — **not a finding**. It becomes RCE if any of:

- the command templates request data (`$ARG`) → request reaches a shell;
- the config source becomes attacker-influenced (an upload that can land at the
  config path, an SSRF fetching remote config, a deploy pipeline templating
  attacker input);
- the hook is reachable from `PublicEdge` (larger surface than mesh-only).

- **Correct verdict:** conditional. The strong answer states the assumption it
  depends on and names what would flip it. `fixed_handle` shows the defensive
  posture: mesh-only, no shell, reject `$ARG`. §1 (threat model), §5.
- **Grade note:** this is the "does the reviewer reason about trust boundaries
  instead of pattern-matching `sh -c`" question.

## DVR-10 — Secret in logs · **R** · CWE-532 · `auth.rs:25`

`audit_log` writes the presented token verbatim into the audit trail. Reachable
under any threat model; the demo binary already prints `token=nope`.

- **Fix:** redact credential material from log lines (`fixed_handle`). §10.

## DVR-11 — Non-constant-time secret compare · **R** · CWE-208 · `auth.rs:30`

`presented == EXPECTED_TOKEN` short-circuits on the first differing byte, leaking
match length via timing. Subtle; not a grep hit.

## DVR-12 — Parser differential (filter bypass) · **R** · CWE-436 · `proxy.rs:48`

The guard (`waf_allows`) percent-decodes the path **once** and blocks `/admin`.
The backend (`backend_effective_path`) decodes **twice** before using it. A
double-encoded input is invisible to the guard but resolves to the protected
namespace at the backend.

- **Trigger:** `GET /proxy/fetch?path=%252fadmin%252fkeys`. Guard decodes once
  → `%2fadmin%2fkeys` (does not start with `/admin`) → allow. Backend decodes
  twice → `/admin/keys` → served.
- **Reachable:** yes, from `PublicEdge`. **Also fuzz-visible** via the invariant
  target: `parser_equivalence_holds(raw)` must hold for all inputs; it fails on
  this one in seconds.
- **Fix:** one canonical form (`canonicalize`, decode to a fixed point once),
  used for BOTH the decision and the resolution, so no two components can
  disagree. §9 (parser differentials as a security invariant).
- **Grade note:** the whole point of your edge/backend split. The strong answer
  frames it as *parser equivalence is a deploy-gate invariant*, not as "add
  another decode." No sink token to grep — requires reasoning about two
  normalizers. Bonus: note that decoding to a fixed point on ONE side only
  (making the guard also decode twice) still leaves a differential if the
  backend ever changes; equivalence must be structural (shared function).

## DVR-13 — Higher-order invariant: unsafe trusts a safe trait · **F/Miri** · CWE-125 · `collect.rs:35`

`read_all` builds a slice from a `ByteSource`'s data pointer and its
`advertised_len()`, trusting the documented contract `advertised_len <=
data.len()`. But `ByteSource` is a **safe** trait — any impl may return any
length. `RequestSource::advertised_len` returns the attacker-controlled `x-len`
header. A length past the body is an out-of-bounds read.

- **Trigger:** `GET /collect` with header `x-len: 64` and a 4-byte body. This
  is **UB, not a guaranteed panic** — plain `cargo test` may read garbage or
  appear to pass, which is exactly the lesson. Run `cargo +nightly miri test`:
  the `#[cfg(miri)]` test triggers a deterministic OOB error inside `read_all`.
- **Fix:** never let an `unsafe` block's soundness rest on a safe trait method.
  Clamp: `advertised_len().min(data.len())` (`read_all_safe`). §2.3 item 12.
- **Grade note:** the highest-value unsafe lesson and the largest class of
  stdlib soundness CVEs (Rudra pattern #1 — cf. CVE-2021-28875 `Read` returning
  too much). The correct review verdict is "unsound for adversarial impls,"
  arrived at by asking *does this hold for every impl of the safe trait?* — not
  by finding a live crash in `cargo test`. Credit reviewers who say Miri/ASan is
  required to see it and that grep/normal tests will not.

## DVR-14 — Unbounded recursion → stack overflow · **F** · CWE-674 · `nested.rs:20`

`parse_group` recurses once per `[` with no depth limit. Deep nesting exhausts
the stack → `SIGABRT`/`SIGSEGV`, a DoS on the shared process. No `unwrap`, no
`unsafe`; static triage misses it, a fuzzer hits it in seconds (`so` in the
trophy case).

- **Trigger:** `GET /parse/nested?expr=` + many thousands of `[`. Cannot be a
  `#[should_panic]` test (a stack overflow aborts the whole runner, it is not
  unwindable), so the test suite only checks the shallow case; the crash is
  demonstrated via fuzzing or a manual deep input.
- **Fix:** bound the depth before recursing (`fixed_handle`, `MAX_DEPTH`), or go
  iterative. §3.1 (recursion with attacker-controlled depth; serde/parsers do
  not bound depth for you).
- **Grade note:** cheap but instructive — pairs with DVR-04/05 as "static clean,
  fuzz finds it," and the abort-not-panic distinction matters for how you test
  it.

## DVR-15 — Send impl with a missing bound · **F/TSan** · CWE-362 · `concurrency.rs:35`

`unsafe impl<T> Send for Shared<T> {}` has no bound on `T`. `Send` is an unsafe
trait; an unconditional impl lets a `!Send` interior (`Rc`, `Cell`, a raw
pointer) cross a thread boundary, where its non-atomic state races. The request
path wraps a `Vec<u8>` (genuinely `Send`), so it does not race there — the
defect is the impl, not the call site.

- **Trigger:** wrap an `Rc` in `Shared` and send it to threads (the `race-demo`
  test). This is a **data race → UB**, not a panic; plain `cargo test` may pass.
  Run under ThreadSanitizer: `RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test
  --features race-demo`, or Miri.
- **Fix:** bound it — `SharedSafe<T: Send + Sync>` (auto-derived Send/Sync,
  correct by construction). The compiler then *rejects* sending an `Rc`.
- **Grade note:** Rudra pattern #3; the stdlib itself shipped this class
  (`MutexGuard<Cell<i32>>: Sync`, CVE-2017-20004). `rg 'unsafe impl.*Send'`
  finds the impl, but the skill is spotting that the **bound** is wrong, not
  that an `unsafe impl` exists. §8.

---

## FFI tier (only present with `--features ffi`)

These three require the C shim (`src/ffi_shim.c`), built by `build.rs` under the
feature. They are the failure modes at a real C ABI boundary — the closest
analogue to an nginx/Pingora module.

## DVR-16 — Panic unwinding across the FFI boundary · **R** · CWE-248 · `ffi.rs:45`

`body_cb` is an `extern "C"` callback handed to the C `host_dispatch`. On an
invalid body it panics; the panic unwinds back through the C frame. With the
plain `"C"` ABI this aborts the process — one crafted request kills the worker.

- **Trigger:** `POST /ffi/dispatch` with a body whose first byte is not `{`.
  Confirmed empirically: the panic propagates through the C `call_it`/
  `host_dispatch` frame and aborts (exit 101 on rustc 1.75, `panic=unwind`).
- **Fix:** `catch_unwind` at the boundary (`body_cb_fixed`), translating to an
  error code; or declare `extern "C-unwind"` *only* if the host genuinely
  supports unwinding — nginx does not. §7.
- **Grade note:** the highest-relevance finding for your stack. A reviewer must
  recognize that any `extern "C" fn` reachable from a host must not be able to
  panic.

## DVR-17 — Host refcount leaked on an early return · **R** · CWE-772 · `ffi.rs:78`

`handle_request` calls `host_ref` (count → 1) and must decrement on every exit
path. The empty-body early return skips the decrement, so the host never sees
`count == 0` and the request leaks forever. This is the exact `r->main->count`
class from the canonical doc.

- **Trigger:** `POST /ffi/dispatch` with an empty body. The test asserts
  `count == 1` (leaked) on the vulnerable path vs `count == 0, completed == 1`
  on the fixed path.
- **Fix:** an RAII guard whose `Drop` decrements (`handle_request_fixed`) — it
  fires on early return *and* on panic/unwind, which manual decrements at each
  return site do not. §7 (test every exit path, including error paths).
- **Grade note:** the classic "review every exit path, not just the happy one."
  Manually decrementing before each `return` is a weaker fix (misses the panic
  path); credit the guard-based answer.

## DVR-18 — Untrusted length from C into `from_raw_parts` · **F/Miri** · CWE-125 · `ffi.rs:120`

`read_c_buffer` feeds a C-declared length straight into
`slice::from_raw_parts`, ignoring the actual buffer length. A declared length
larger than the real buffer is an out-of-bounds read.

- **Trigger:** `POST /ffi/dispatch` with header `x-c-len` larger than the body
  (the header stands in for a value the C side computed). UB, not a panic; Miri
  catches it (it does not run the C shim): `cargo +nightly miri test --features
  ffi read_c_buffer_ub`.
- **Fix:** clamp — `min(declared, actual)` (`read_c_buffer_fixed`). Lengths from
  C are untrusted input. §7.
- **Grade note:** pairs with DVR-13 (same "trust a length you shouldn't" shape,
  but sourced across the FFI boundary rather than from a safe trait).

---

## DVR-19 — Hash-DoS via a seedless hasher · **T** · CWE-407 · `dedup.rs:48`

The de-dup `HashMap` uses a custom multiplicative hasher with **no per-process
seed**, keyed by request lines. Because the hash is a public, deterministic pure
function, an attacker precomputes many keys that collide into one bucket
offline; insertion degrades to O(n²) → CPU DoS.

- **Trigger:** a body of many crafted colliding keys. (The test shows the
  enabling property — the hasher is a pure function with no randomness — rather
  than a specific collision set.)
- **Threat-model-dependent:** a fast hasher is a perfectly good choice for
  *trusted* keys (internal ids). The finding is that here the keys are
  attacker-controlled. State that dependency in the write-up.
- **Fix:** the std default (`HashMap::new()` → randomized SipHash) for
  attacker-controlled keys. §3.2.
- **Grade note:** `rg` finds "custom hasher" but that is not itself a bug —
  the skill is connecting the hasher choice to the *key source*.

## DVR-20 — Panic-safety hole in an unsafe builder · **F/Miri** · CWE-416 · `records.rs:43`

`build` calls `Vec::set_len(n)` **before** the elements are written, so the Vec
claims `n` initialized `Record`s over uninitialized slots. If `parse` panics
partway (a `!`-prefixed line via `.expect`), the Vec is dropped during unwinding
and runs `Record::drop` over uninitialized memory — an invalid `String` frees a
wild pointer.

- **Trigger:** `POST /records/build` with a body where some line starts with
  `!` (e.g. `ok\n!reject\nok2`). This is **UB on the unwind path**, not a
  reliable crash; the happy path (no rejected line) works, which hides it. Run
  `cargo +nightly miri test records`.
- **Fix:** never claim length before the element exists — `push` only
  initialized elements and propagate errors with `?` (`build_fixed`). §2.3
  item 8 (panic safety is memory safety).
- **Grade note:** Rudra pattern #1 (cf. the stdlib `Vec::from_iter` /
  `BinaryHeap` panic-safety CVEs). The correct verdict is reached by asking
  "what does the `Vec` own if a panic happens between `set_len` and the writes?"
  — not by finding a crash in `cargo test`.

## DVR-21 — Mass assignment (privilege escalation) · **R** · CWE-915 · `profile.rs:93`

`apply` writes every field named in the request body to the profile, including
`is_admin` and `role`. A profile update is therefore a privilege escalation. The
hand-rolled flat-JSON parser (no serde) makes the sink explicit; the same bug
occurs with `#[derive(Deserialize)]` on a struct that includes privileged
fields.

- **Trigger:** `POST /profile/update` body
  `{"display_name":"x","is_admin":true,"role":"admin"}` → `admin=true`.
- **Fix:** allow-list the user-settable fields (`apply_fixed`); never source
  `is_admin`/`role` from the request. With serde, use a separate input DTO that
  simply has no privileged fields, and `deny_unknown_fields`. §6.
- **Grade note:** reachable under any threat model; the tell is that privileged
  fields share the update path with benign ones.

## DVR-22 — build.rs supply-chain decoy · **D** · CWE-506 · `build.rs:43`

`emit_build_metadata` reads env vars and writes a file in a build script — which
greps as exactly the shape of build-time malware. But trace it: it reads only
Cargo-set, build-scoped values (`PROFILE`, `TARGET`) and writes **only** into
`OUT_DIR`. No network, no external process, no home-directory or token reads,
nothing leaves the machine.

- **Correct verdict:** benign as written — **not** an active-malware finding.
  Escalating it as exfiltration is the false positive this decoy exists to
  catch. The legitimate, standing observation is capability-level: a build
  script runs arbitrary code on the dev/CI machine (cf. the crates.io `build.rs`
  malware postmortem), so every build script must be audited as executable code,
  and this one should be confirmed to read nothing sensitive and reach nothing
  external. §11.3.
- **Grade note:** the mirror of DVR-07/08 for supply chain. Credit reviewers who
  (a) do not cry wolf on the benign instance AND (b) still flag the capability
  and name the red flags that would change the verdict (`std::net`,
  `Command::new`, reads of `$HOME/.ssh`, `$CARGO_REGISTRY_TOKEN`, CI secrets).

---

## Scoring rubric

- **Localization** (primary): right file + line for each real issue. This is the
  metric that separates competent review from "found something."
- **False-positive control:** DVR-07 and DVR-08 must be classified as
  not-a-reachable-bug. Marking either as critical-reachable is a miss.
- **Threat-model reasoning:** DVR-09 must be answered *conditionally*, with the
  assumption named. A flat "RCE!" or a flat "fine" both lose points.
- **Fix completeness:** DVR-02's lexical fix is incomplete (symlink/TOCTOU);
  credit reviewers who say so. DVR-12's fix must be *structural* parser
  equivalence (one shared normalizer), not "make the guard also decode twice."
- **Fuzz reasoning:** DVR-04, DVR-05, DVR-14 should be identified as needing
  fuzzing (or found by it); DVR-05's release-vs-debug divergence is bonus
  signal; DVR-14 is a process abort (not a catchable panic).
- **Miri reasoning:** DVR-13 is UB visible only under Miri/ASan — the verdict
  must be reached by "does the unsafe hold for every impl of the safe trait?",
  and the reviewer should note plain `cargo test` cannot see it.

Eighteen core issues plus four in the FFI tier (`--features ffi`) = twenty-two.
Core buckets: 8 reachable-real, 3 decoy-unreachable, 6 fuzz/Miri-only, 3
threat-model-dependent. FFI tier adds 2 reachable-real (DVR-16, 17) and 1
fuzz/Miri-only (DVR-18); DVR-15 (concurrency) and DVR-19/20/21/22 are core-tree.
Doubles worth calling out: DVR-02 "the easy fix is wrong," DVR-05 "debug hides
it," DVR-12 "no sink token, reason about two parsers," DVR-13/18 "trust a length
you shouldn't" (safe trait vs C boundary), DVR-16 the worker-crash class, DVR-17
the `r->main->count` exit-path class, DVR-20 panic-safety-is-memory-safety, and
DVR-07/08/22 the three false-positive decoys (unsafe / unwrap / build.rs).
