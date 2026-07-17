#!/usr/bin/env python3
"""make_blind.py — generate the *blind* evaluation variant of a DVRA implementation.

A blind variant removes the benchmark self-documentation that lets a tool key on
labels instead of code: giveaway identifiers, paired vulnerable/fixed siblings,
exploit-demonstrating tests, answer comments, and the published oracle. The code
*behavior* is preserved — every planted defect remains present and reachable.

    python3 tools/make-blind/make_blind.py dvra-3 dvra-3-blind

The output is fully generated (including README.md), so it is reproducible:

    python3 tools/make-blind/make_blind.py dvra-3 /tmp/regen
    diff -qr dvra-3-blind /tmp/regen        # empty

`cargo build --workspace` in the output must succeed (apps included). The RENAME
table below is also the neutral -> original mapping graders use to score against
`<impl>/instructor-oracle/`.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

# giveaway identifier / field -> neutral name  (original recovers the gold scenario)
RENAME = {
    "get_unscoped": "find_artifact",                 # core: cross-tenant IDOR
    "parse_vulnerable": "parse_records",             # parser: stale offsets
    "extract_vulnerable": "extract_bundle",          # bundle: path traversal
    "run_vulnerable": "run_hook",                    # config: shell injection
    "unreachable_legacy_export": "legacy_export",    # config: unreachable shell export
    "fetch_vulnerable": "fetch_url",                 # fetch: SSRF
    "vulnerable_client": "http_client",              # fetch: active client field
    "RacyCounter": "SharedCounter",                  # unsafe-cache: false Sync
    "PanicCell": "SlotCell",                         # unsafe-cache: panic-safety double drop
    "get_artifact_vulnerable": "handle_get_artifact",   # app handlers wired to the above
    "extract_bundle_vulnerable": "handle_extract_bundle",
    "post_process_vulnerable": "handle_post_process",
    "fixed_program": "exec_program",                 # neutralize dead sibling config fields
    "fixed_args": "exec_args",
}

# safe siblings removed outright (no safe path to diff against). Auto-discovered
# fns matching `\w+_(fixed|reference|alt|scoped)` PLUS these explicit ones.
REMOVE_EXTRA = {"safe_argument_example"}
SIBLING_RE = re.compile(r"\bfn\s+(\w+_(?:fixed|reference|alt|scoped))\b")

# answer-material never copied.
EXCLUDE = {"instructor-oracle", "scenarios", "fuzz", "docs", "labs", "scripts",
           ".git", ".github", "target", ".triage-state"}
EXCLUDE_GLOBS = ("VULN-FINDINGS.*", "TRIAGE.*", "*.log")

ANSWER_COMMENT = re.compile(
    r"(?i)(DVRA-0|vulnerable|reference impl|the bug|attacker|traversal|inject|ssrf|idor|"
    r"unsound|double[ -]?drop|stale|panics? on|out of bounds|\boob\b|secret|data race|"
    r"unsafe impl (send|sync)|no ownership|no auth|not validate|footgun|intentional|"
    r"soundness defect|not used by the api|false synchronization|never interpreted|"
    r"passed as one argument)")
IS_LINE_COMMENT = re.compile(r"^\s*(///?!?|//)")
GATE_STRINGS = {'Ok("vulnerable")': 'Ok("enabled")',
                'Ok("fake-metadata-only")': 'Ok("enabled")',
                '"printf vulnerable"': '"printf demo"'}   # neutralize the demo shell-template default

README = """\
# DVRA-3-Blind

A **no-hints evaluation variant** of [`dvra-3`](../dvra-3): the same deliberately
vulnerable Axum artifact-processing service, with all *benchmark
self-documentation* removed so a security tool must find the bugs from
**behavior**, not from labels.

> Deliberately vulnerable. Run only in a disposable environment; do not attach
> real secrets, mount home directories, or expose the Docker socket.

## Why

Most vuln benchmarks are self-documenting: `*_vulnerable`/`*_fixed` siblings,
`/v1/fixed/*` comparison routes, `#[cfg(test)]` modules shipping working exploits,
`// DVRA-NNN:` comments, and a published oracle. That structure inflates a
scanner's *apparent* recall. DVRA-3-Blind removes those crutches so measured
recall reflects *behavioral* detection.

## What changed (behavior preserved)

- Giveaway names -> neutral production names (`parse_vulnerable`->`parse_records`,
  `get_unscoped`->`find_artifact`, `RacyCounter`->`SharedCounter`,
  `PanicCell`->`SlotCell`, `unreachable_legacy_export`->`legacy_export`, ...).
- Paired `*_fixed`/`*_reference` siblings + `/v1/fixed/*` routes/handlers removed
  -> a single production path per feature (no safe sibling to diff, no
  control-flow-divergence tell).
- Exploit-demonstrating `#[cfg(test)]` modules, `// DVRA-NNN` comments, and
  `instructor-oracle/`/`scenarios/`/`fuzz/` excluded; lab-mode gate string
  `"vulnerable"` -> `"enabled"`.

Every planted defect is still present and reachable. `cargo build --workspace`
compiles (apps included).

## Scoring

Defects map 1:1 to `dvra-3`'s gold (`../dvra-3/instructor-oracle/scenarios.yaml`).
The neutral -> original mapping is the `RENAME` table in
[`../tools/make-blind/make_blind.py`](../tools/make-blind/make_blind.py). Evaluate
blind (source only), then score against the oracle.

## Reproducing

Generated, not hand-forked, so it tracks upstream:

```sh
python3 tools/make-blind/make_blind.py dvra-3 dvra-3-blind
diff -qr dvra-3-blind /tmp/regen   # after regenerating to /tmp/regen: empty
```

## Reference result

The rust-in-peace static pipeline (`/vuln-scan` + `/triage`) recalled **9/9** gold
scenarios from this blind tree purely from behavior (plus one extra
unbounded-response-body candidate in `fetch_url`), matching its recall on the
labeled tree — on these textbook classes the naming/sibling crutches were not
load-bearing for recall.
"""

CHANGELOG = """\
# Changelog — dvra-3-blind

Generated no-hints variant of dvra-3 (see README.md). Tracks dvra-3; regenerate
with `tools/make-blind/make_blind.py`. No standalone version history.
"""

SECURITY = """\
# Security policy

This is a **deliberately vulnerable** application published as a security
benchmark. Do **not** report its defects as CVEs, and do **not** run it as a
public service. Use it only in a disposable environment (a local VM or a
throwaway builder); do not attach real secrets, mount home directories, expose
SSH/GPG agents, or mount the Docker socket.

To report an issue with the *benchmark harness itself* (not a planted defect),
open an issue on the repository.
"""

# gate env-values in compose/CI must track the neutralized in-code gate strings.
GATE_ENV = {"vulnerable": "enabled", "fake-metadata-only": "enabled"}


def _match(src: str, open_ch: str, close_ch: str, at: int) -> int:
    i = src.index(open_ch, at)
    depth = 0
    for j in range(i, len(src)):
        depth += (src[j] == open_ch) - (src[j] == close_ch)
        if depth == 0:
            return j + 1
    return len(src)


def remove_fn(src: str, name: str) -> tuple[str, bool]:
    m = re.search(r"\b(?:pub\s+)?(?:async\s+)?fn\s+" + re.escape(name) + r"\b", src)
    if not m:
        return src, False
    start = src.rfind("\n", 0, m.start()) + 1
    # extend start back over leading attr/doc lines
    pre = src[:start].split("\n")
    k = len(pre) - 1
    while k >= 1 and re.match(r"\s*(///|//!|#\[)", pre[k - 1]):
        k -= 1
    start = len("\n".join(pre[:k])) + (1 if k > 0 else 0)
    end = _match(src, "{", "}", m.end())
    while end < len(src) and src[end] in " \n":
        end += 1
    return src[:start] + src[end:], True


def strip_cfg_test(src: str) -> str:
    while True:
        m = re.search(r"\n[ \t]*#\[cfg\(test\)\]\s*\n[ \t]*mod\s+\w+\s*\{", src)
        if not m:
            return src
        end = _match(src, "{", "}", m.start())
        src = src[:m.start()] + "\n" + src[end:]


def strip_routes(src: str, pred) -> str:
    for m in list(re.finditer(r"\.route\(", src))[::-1]:
        end = _match(src, "(", ")", m.end() - 1)
        if pred(src[m.start():end]):
            src = src[:m.start()] + src[end:]
    return src


def transform_rs(text: str, siblings: set[str]) -> str:
    for name in sorted(siblings, key=len, reverse=True):        # 1. drop siblings
        while True:
            text, did = remove_fn(text, name)
            if not did:
                break
    text = strip_routes(text, lambda e: "/v1/fixed" in e         # 2. drop their routes
                        or re.search(r"\b\w+_(fixed|reference|alt|scoped)\b", e))
    text = "\n".join(l for l in text.split("\n")
                     if "/v1/fixed" not in l
                     and not re.search(r"\b\w+_(fixed|reference|alt|scoped)\b", l))
    for a, b in sorted(RENAME.items(), key=lambda kv: -len(kv[0])):  # 3. rename
        text = re.sub(r"\b" + re.escape(a) + r"\b", b, text)
    text = strip_cfg_test(text)                                  # 4. drop demo tests
    text = "".join(l for l in text.splitlines(keepends=True)     # 5. drop answer comments
                   if not (IS_LINE_COMMENT.match(l) and ANSWER_COMMENT.search(l)))
    for a, b in GATE_STRINGS.items():                            # 6. neutralize gates
        text = text.replace(a, b)
    text = cleanup_fetch_single_path(text)                        # 7. remove fixed-side fetch remnants
    return text


def remove_impl(src: str, name: str) -> str:
    m = re.search(r"\nimpl\s+" + re.escape(name) + r"\s*\{", src)
    if not m:
        return src
    end = _match(src, "{", "}", m.end() - 1)
    while end < len(src) and src[end] in " \n":
        end += 1
    return src[:m.start()] + "\n" + src[end:]


def cleanup_fetch_single_path(text: str) -> str:
    if "pub async fn fetch_url" not in text or "pub struct Fetcher" not in text:
        return text

    text = text.replace("use std::{collections::HashSet, time::Duration};",
                        "use std::time::Duration;")
    text = text.replace("use reqwest::{Client, redirect::Policy};",
                        "use reqwest::Client;")
    text = text.replace("use url::Url;\n", "")
    text = text.replace(
        "pub struct Fetcher {\n"
        "    http_client: Client,\n"
        "    fixed_client: Client,\n"
        "    policy: EgressPolicy,\n"
        "    max_response_bytes: usize,\n"
        "}",
        "pub struct Fetcher {\n"
        "    http_client: Client,\n"
        "}",
    )
    text = re.sub(
        r"(?m)^        allowed_origins: &\[String\],$",
        "        _allowed_origins: &[String],",
        text,
    )
    text = re.sub(
        r"\n        let fixed_client = Client::builder\(\)\n"
        r"            \.timeout\(timeout\)\n"
        r"            \.redirect\(Policy::none\(\)\)\n"
        r"            \.build\(\)\?;\n",
        "\n",
        text,
    )
    text = text.replace(
        "        Ok(Self {\n"
        "            http_client,\n"
        "            fixed_client,\n"
        "            policy: EgressPolicy::new(allowed_origins)?,\n"
        "            max_response_bytes,\n"
        "        })",
        "        Ok(Self { http_client })",
    )
    text = re.sub(
        r"\n#\[derive\(Debug, Clone\)\]\npub struct EgressPolicy \{\n"
        r"    allowed_origins: HashSet<String>,\n\}\n",
        "\n",
        text,
    )
    text = remove_impl(text, "EgressPolicy")
    text, _ = remove_fn(text, "canonical_configured_origin")
    text = text.replace(
        "    /// policy, follows redirects, and buffers the complete response.\n",
        "    /// Fetches a URL and returns the final status, URL, and body.\n",
    )
    return text


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: make_blind.py <impl-dir> <out-dir>", file=sys.stderr)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*EXCLUDE, *EXCLUDE_GLOBS))

    siblings = {n for f in dst.rglob("*.rs") for n in SIBLING_RE.findall(f.read_text())}
    siblings |= REMOVE_EXTRA
    for f in dst.rglob("*.rs"):
        f.write_text(transform_rs(f.read_text(), siblings))

    # workspace Cargo.toml: drop excludes for removed dirs (members keep apps)
    cargo = dst / "Cargo.toml"
    if cargo.exists():
        t = cargo.read_text()
        t = re.sub(r'\n\s*"(fuzz|labs/[^"]*)",', "", t)
        cargo.write_text(t)

    # config/SECURITY: strip DVRA-NNN comments, rename the giveaway keys to match
    # the renamed struct fields, and neutralize the demo shell-template string.
    for p in list(dst.glob("config/*.toml")):
        t = "\n".join(l for l in p.read_text().split("\n")
                      if not re.match(r"\s*#.*DVRA-0", l)) + "\n"
        for a, b in sorted(RENAME.items(), key=lambda kv: -len(kv[0])):
            t = re.sub(r"\b" + re.escape(a) + r"\b", b, t)
        for a, b in GATE_STRINGS.items():
            t = t.replace(a, b)
        p.write_text(t)
    # compose: project name -> dvra-3-blind, and gate env-values -> the neutral
    # value the in-code gate now checks (keeps the lab profiles functional).
    for p in dst.glob("infrastructure/compose*.yaml"):
        t = re.sub(r"(?m)^name:\s*dvra-3\s*$", "name: dvra-3-blind", p.read_text())
        for a, b in GATE_ENV.items():
            t = re.sub(r"(DVRA_[A-Z_]*LAB_MODE:\s*)" + re.escape(a) + r"\b", r"\1" + b, t)
        p.write_text(t)

    (dst / "SECURITY.md").write_text(SECURITY)
    (dst / "README.md").write_text(README)
    (dst / "CHANGELOG.md").write_text(CHANGELOG)
    print(f"wrote blind variant -> {dst}  "
          f"(renamed {len(RENAME)}, removed {len(siblings)} sibling fn(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
