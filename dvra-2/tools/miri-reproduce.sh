#!/usr/bin/env sh
set -eu

case "${1:-}" in
  DVRA-008|008)
    package=dvra-unsafe-cache
    test_name=dvra_008_miri_detects_double_drop_after_callback_panic
    ;;
  DVRA-013|013)
    package=dvra-binary-parser
    test_name=dvra_013_miri_reaches_the_unregistered_decoder_directly
    ;;
  *)
    echo "usage: tools/miri-reproduce.sh <DVRA-008|DVRA-013>" >&2
    exit 2
    ;;
esac

mkdir -p /tmp/dvra "$CARGO_HOME" "$HOME"
log="/tmp/dvra/${test_name}.log"

set +e
cargo +nightly-2025-04-03 miri test -p "$package" "$test_name" -- --nocapture >"$log" 2>&1
status=$?
set -e
cat "$log"

if [ "$status" -eq 0 ]; then
  echo "expected Miri to reject ${test_name}, but it passed" >&2
  exit 1
fi

grep -E "Undefined Behavior|error:" "$log" >/dev/null
echo "Miri reproduced ${test_name}"
