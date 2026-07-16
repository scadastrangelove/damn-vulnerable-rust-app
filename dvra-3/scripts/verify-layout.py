#!/usr/bin/env python3
"""Offline structural checks that require only Python 3.11+."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED = [
    "Cargo.toml",
    "apps/api/src/main.rs",
    "apps/metadata-service/src/main.rs",
    "crates/parser/src/lib.rs",
    "crates/fetch/src/lib.rs",
    "crates/bundle/src/lib.rs",
    "crates/unsafe-cache/src/lib.rs",
    "fuzz/fuzz_targets/differential_parser.rs",
    "instructor-oracle/scenarios.yaml",
    "infrastructure/compose.yaml",
    "infrastructure/compose.ssrf.yaml",
]

EXPECTED_IDS = {
    "DVRA-001",
    "DVRA-002",
    "DVRA-003",
    "DVRA-004",
    "DVRA-005",
    "DVRA-006A",
    "DVRA-006B",
    "DVRA-007",
    "DVRA-008",
    "DVRA-009",
}

EXPECTED_PUBLIC_FILES = {
    "DVRA-001.md",
    "DVRA-002.md",
    "DVRA-003.md",
    "DVRA-004.md",
    "DVRA-005.md",
    "DVRA-006.md",
    "DVRA-007.md",
    "DVRA-008.md",
    "DVRA-009.md",
}


def main() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        print("missing required files:", *missing, sep="\n- ", file=sys.stderr)
        return 1

    parsed_toml: dict[pathlib.Path, dict] = {}
    for path in ROOT.rglob("*.toml"):
        with path.open("rb") as handle:
            parsed_toml[path] = tomllib.load(handle)

    workspace = parsed_toml[ROOT / "Cargo.toml"]["workspace"]
    package_names: set[str] = set()
    for member in workspace["members"]:
        manifest = ROOT / member / "Cargo.toml"
        if manifest not in parsed_toml:
            print(f"workspace member has no manifest: {member}", file=sys.stderr)
            return 1
        package_name = parsed_toml[manifest]["package"]["name"]
        if package_name in package_names:
            print(f"duplicate workspace package name: {package_name}", file=sys.stderr)
            return 1
        package_names.add(package_name)

    seed = (ROOT / "fuzz/corpus/differential_parser/escape_before_second_record").read_bytes()
    expected_seed = bytes.fromhex("445652410201021b000201aa")
    if seed != expected_seed:
        print(f"unexpected fuzz seed: {seed.hex()}", file=sys.stderr)
        return 1

    traversal_fixture = (ROOT / "scenarios/fixtures/DVRA-008-traversal.dvb").read_bytes()
    if not traversal_fixture.startswith(b"DVB1\x01") or b"../other-job.txt" not in traversal_fixture:
        print("unexpected DVRA-008 traversal fixture", file=sys.stderr)
        return 1

    oracle_text = (ROOT / "instructor-oracle/scenarios.yaml").read_text(encoding="utf-8")
    scenario_ids = set(re.findall(r"^\s*- id:\s*(DVRA-[0-9A-Z]+)\s*$", oracle_text, re.MULTILINE))
    if scenario_ids != EXPECTED_IDS:
        print(f"oracle IDs differ: {sorted(scenario_ids)}", file=sys.stderr)
        return 1

    public_files = {path.name for path in (ROOT / "scenarios/public").glob("DVRA-*.md")}
    if public_files != EXPECTED_PUBLIC_FILES:
        print(f"public scenario files differ: {sorted(public_files)}", file=sys.stderr)
        return 1

    api_source = (ROOT / "apps/api/src/main.rs").read_text(encoding="utf-8")
    for required_route in (
        '"/v1/bundles/{job_id}"',
        '"/v1/fixed/bundles/{job_id}"',
        "require_enabled()",
        "DefaultBodyLimit::max(1024 * 1024)",
    ):
        if required_route not in api_source:
            print(f"DVRA-008 API invariant missing: {required_route}", file=sys.stderr)
            return 1

    bundle_source = (ROOT / "crates/bundle/src/lib.rs").read_text(encoding="utf-8")
    for required_fragment in (
        "destination.join(entry.path)",
        "Component::Normal",
        "extract_vulnerable",
        "extract_fixed",
    ):
        if required_fragment not in bundle_source:
            print(f"bundle scenario invariant missing: {required_fragment}", file=sys.stderr)
            return 1

    for required_route in ('"/v1/fetch"', '"/v1/fixed/fetch"'):
        if required_route not in api_source:
            print(f"DVRA-009 API route missing: {required_route}", file=sys.stderr)
            return 1

    fetch_source = (ROOT / "crates/fetch/src/lib.rs").read_text(encoding="utf-8")
    for required_fragment in (
        "fetch_vulnerable",
        "fetch_fixed",
        "Policy::none()",
        "allowed_origins",
        "max_response_bytes",
        "response.bytes().await?",
        "while let Some(chunk) = response.chunk().await?",
    ):
        if required_fragment not in fetch_source:
            print(f"SSRF scenario invariant missing: {required_fragment}", file=sys.stderr)
            return 1

    metadata_source = (ROOT / "apps/metadata-service/src/main.rs").read_text(encoding="utf-8")
    for required_fragment in (
        "DVRA_FAKE_METADATA_TOKEN",
        "/redirect-to-credentials",
        "/latest/meta-data/iam/security-credentials/dvra",
    ):
        if required_fragment not in metadata_source:
            print(f"fake metadata invariant missing: {required_fragment}", file=sys.stderr)
            return 1

    default_config = parsed_toml[ROOT / "config/dvra.toml"]
    storage_root = str(default_config["storage"]["root"])
    if not storage_root.startswith("/tmp/dvra/"):
        print(f"default storage root is outside disposable /tmp: {storage_root}", file=sys.stderr)
        return 1

    allowed_origins = default_config["fetch"]["allowed_origins"]
    if any("metadata" in origin or "127.0.0.1" in origin for origin in allowed_origins):
        print("fixed fetch allowlist must not include metadata or loopback", file=sys.stderr)
        return 1
    if default_config["fetch"]["max_response_bytes"] > 1024 * 1024:
        print("fixed fetch response ceiling is unexpectedly large", file=sys.stderr)
        return 1

    compose = (ROOT / "infrastructure/compose.yaml").read_text(encoding="utf-8")
    for required_fragment in (
        '"127.0.0.1:3000:3000"',
        "read_only: true",
        "no-new-privileges:true",
        "ingress:",
        'com.docker.network.bridge.enable_ip_masquerade: "false"',
        "internal: true",
        "profiles:",
        "ssrf-lab",
        "/usr/local/bin/dvra-metadata-service",
    ):
        if required_fragment not in compose:
            print(f"compose safety control missing: {required_fragment}", file=sys.stderr)
            return 1

    ssrf_override = (ROOT / "infrastructure/compose.ssrf.yaml").read_text(encoding="utf-8")
    for required_fragment in (
        "DVRA_SSRF_LAB_MODE: fake-metadata-only",
        "DVRA_ACK_INSECURE: I_UNDERSTAND",
        "metadata",
    ):
        if required_fragment not in ssrf_override:
            print(f"SSRF compose override missing: {required_fragment}", file=sys.stderr)
            return 1

    labctl = (ROOT / "scripts/labctl").read_text(encoding="utf-8")
    dangerous_block = labctl.split("  run-dangerous)", 1)[1].split("  run-ssrf)", 1)[0]
    if "DVRA_SSRF_LAB_MODE" in dangerous_block:
        print("run-dangerous must not enable the SSRF gate", file=sys.stderr)
        return 1
    for required_fragment in ("--profile ssrf-lab", "stop-ssrf", "--remove-orphans"):
        if required_fragment not in labctl:
            print(f"SSRF lifecycle control missing: {required_fragment}", file=sys.stderr)
            return 1

    metadata_block = compose.split("  metadata:", 1)[1].split("\nnetworks:", 1)[0]
    if "\n    ports:" in metadata_block:
        print("fake metadata service must not publish a host port", file=sys.stderr)
        return 1
    if "\n      - ingress" in metadata_block:
        print("fake metadata service must stay off the ingress network", file=sys.stderr)
        return 1

    root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if 'reqwest = { version = "=0.12.15"' not in root_manifest:
        print("reqwest must remain exactly pinned for benchmark reproducibility", file=sys.stderr)
        return 1

    dockerfile = (ROOT / "infrastructure/Dockerfile").read_text(encoding="utf-8")
    if "dvra-metadata-service" not in dockerfile:
        print("container image must include the fake metadata binary", file=sys.stderr)
        return 1
    if "USER 10001:10001" not in dockerfile:
        print("container must run as the unprivileged DVRA user", file=sys.stderr)
        return 1

    print("DVRA offline layout validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
