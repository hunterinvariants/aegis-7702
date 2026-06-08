#!/usr/bin/env bash
# Validate the aegis-7702 detector pack against The Red Guild's 7702-goat -- the public set of
# intentionally-broken EIP-7702 delegates (https://github.com/theredguild/7702-goat). Runs all seven
# detectors and prints which goat vulnerability contract (V0..V6) each one flags, so the README's
# "flags every vulnerability class (V0 through V6)" claim is reproducible rather than asserted.
#
# Prereqs: the pack installed (`pip install -e .`) and `slither` on PATH.
# Usage:   ./run_goat.sh            # clones goat to /tmp, or set GOAT_DIR to an existing checkout
set -euo pipefail
GOAT_DIR="${GOAT_DIR:-/tmp/7702-goat}"
ARGS=eip7702-unprotected-entrypoint,eip7702-recallable-initializer,eip7702-missing-nonce,eip7702-replay-unsafe-sig,eip7702-unsafe-eoa-assumption,eip7702-constructor-state,eip7702-storage-collision
[ -d "$GOAT_DIR" ] || git clone --recursive https://github.com/theredguild/7702-goat "$GOAT_DIR"
( cd "$GOAT_DIR" && slither src --detect "$ARGS" --json /tmp/aegis_goat.json 2>/dev/null || true )
python3 - <<'PY'
import json
d = json.load(open('/tmp/aegis_goat.json'))
hits = {}
for x in (d.get('results') or {}).get('detectors', []):
    f = (((x.get('elements') or [{}])[0]).get('source_mapping') or {}).get('filename_short') or '?'
    hits.setdefault(f, set()).add(x.get('check'))
for f in sorted(hits):
    print("{:<32} {}".format(f, ', '.join(sorted(hits[f]))))
PY
