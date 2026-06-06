# Aegis-7702

A Slither plugin that catches the security bugs specific to EIP-7702 smart-account delegates -- the
ones a normal contract-by-contract review walks straight past.

## Why this exists

EIP-7702 lets a regular wallet (an EOA) borrow a contract's code and run it as itself, in its own
storage. That's useful, but it quietly breaks assumptions that auditors and tools lean on: who
`msg.sender` really is, what's in storage when the code runs, and whether a signature can be
replayed. Slither is the static analyzer most teams reach for, but on its own it has no concept of
delegation -- it looks at each contract in isolation and misses these footguns entirely. Aegis-7702
adds that missing layer as a Slither plugin.

## What it catches

- `eip7702-unprotected-entrypoint` (High) -- an execute/call entrypoint with no caller check; anyone can drive the account.
- `eip7702-recallable-initializer` (High) -- an initializer with no real one-shot guard; re-init and seize the account.
- `eip7702-missing-nonce` (High) -- a signed action with no nonce; replay it at will.
- `eip7702-replay-unsafe-sig` (Medium) -- a signature that doesn't bind chainId; replay it on another chain.
- `eip7702-unsafe-eoa-assumption` (Medium) -- `tx.origin == msg.sender` used as an "is-EOA" check, which 7702 breaks.
- `eip7702-constructor-state` (Medium) -- security state set in the constructor; gone the moment an EOA delegates.
- `eip7702-storage-collision` (Informational) -- plain (non-namespaced) storage; re-delegation can corrupt it. Use ERC-7201.

Full writeups -- with a vulnerable example and the fix for each -- are in `docs/detectors.md`.

## Does it work?

Every detector has to do two things before it ships: fire on a contract we know is broken, and stay
quiet on one we know is safe. The repo ships both, and the check is one command:

    python tests/run_corpus.py
    -> 7/7 detectors pass

We also ran the full pack against The Red Guild's `7702-goat`
(https://github.com/theredguild/7702-goat), the public collection of intentionally-broken 7702
delegates, and it flags every vulnerability class in there (V0 through V6).

## Install

    pip install slither-analyzer
    pip install -e .

## Use it

    slither <target> --detect eip7702-unprotected-entrypoint,eip7702-missing-nonce,eip7702-replay-unsafe-sig

Add the remaining arguments from the list above to run the whole pack.

## Dynamic harnesses

Static flags are the cheap layer. The 7702 bugs that actually bite are multi-transaction -- they only
surface once an account switches delegates or a signature gets reused -- so the detectors are backed
by Foundry harnesses in `harnesses/` that run a delegate under real 7702 conditions and execute the
exploit. Same two-way discipline as the corpus: the attack lands on the broken delegate and reverts
on the safe one.

    forge test
    -> 6/6 (evm_version = prague)

- storage collision -- a value left at slot 0 by one delegate is read as `owner` by the next, and the account is seized. The ERC-7201 namespaced delegate resists.
- missing nonce -- a single signature replays and sends twice; the nonce-tracking version blocks the second send.
- recallable initializer -- a second `initialize` seizes the account; the guarded version reverts.

So a reviewer can watch the exact bug a detector flags actually fire -- not take the flag on faith.

High and Medium findings are real bugs worth reviewing. Informational (storage-collision) is a
"prefer ERC-7201" heads-up, not a vulnerability.

MIT licensed.
