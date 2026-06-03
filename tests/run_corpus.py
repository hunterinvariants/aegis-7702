#!/usr/bin/env python3
"""Two-way corpus proof for the slither-eip7702 detector pack.

For each detector: assert it FIRES on its known-bad case AND stays CLEAN on its safe control.
Run from the project root (slither + solc installed):  python tests/run_corpus.py
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MANIFEST = {
    "eip7702-unprotected-entrypoint": (
        "corpus/vulnerable/UnprotectedDelegate.sol", "corpus/safe/GuardedDelegate.sol"),
    "eip7702-unsafe-eoa-assumption": (
        "corpus/vulnerable/TxOriginGate.sol", "corpus/safe/StubCheckGate.sol"),
    "eip7702-constructor-state": (
        "corpus/vulnerable/ConstructorGuardian.sol", "corpus/safe/InitializerGuardian.sol"),
    "eip7702-recallable-initializer": (
        "corpus/vulnerable/OpenInitializer.sol", "corpus/safe/GuardedInitializer.sol"),
    "eip7702-missing-nonce": (
        "corpus/vulnerable/NoNonceSig.sol", "corpus/safe/NonceSig.sol"),
    "eip7702-replay-unsafe-sig": (
        "corpus/vulnerable/ChainlessSig.sol", "corpus/safe/ChainBoundSig.sol"),
    "eip7702-storage-collision": (
        "corpus/vulnerable/PlainStorageDelegate.sol", "corpus/safe/NamespacedDelegate.sol"),
}


def count_findings(sol_path: str, argument: str) -> int:
    tmp = os.path.join(tempfile.gettempdir(), "slither_eip7702_out.json")
    if os.path.exists(tmp):
        os.remove(tmp)
    proc = subprocess.run(
        ["slither", sol_path, "--detect", argument, "--json", tmp],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    if not os.path.exists(tmp):
        raise RuntimeError(
            f"slither produced no JSON for {sol_path} / {argument}\n"
            f"--- stderr tail ---\n{proc.stderr[-2000:]}"
        )
    with open(tmp) as fh:
        data = json.load(fh)
    dets = (data.get("results") or {}).get("detectors") or []
    return sum(1 for d in dets if d.get("check") == argument)


def main() -> int:
    print("slither-eip7702 -- two-way corpus proof\n")
    passed = failed = 0
    for arg, (bad, safe) in MANIFEST.items():
        nbad = count_findings(bad, arg)
        nsafe = count_findings(safe, arg)
        ok_bad, ok_safe = nbad >= 1, nsafe == 0
        ok = ok_bad and ok_safe
        passed += int(ok)
        failed += int(not ok)
        print(f"  [{'OK  ' if ok else 'FAIL'}] {arg}")
        print(f"          vuln {bad}  -> {nbad} (expect >=1) {'OK' if ok_bad else 'XX'}")
        print(f"          safe {safe} -> {nsafe} (expect 0)   {'OK' if ok_safe else 'XX'}")
    total = passed + failed
    print(f"\n{passed}/{total} detectors pass the two-way proof")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
