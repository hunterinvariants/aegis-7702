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

| Argument | What it flags | Severity |
| :--- | :--- | :--- |
| `eip7702-unprotected-entrypoint` | An execute/call entrypoint with no caller check -- anyone can drive the account | High |
| `eip7702-recallable-initializer` | An initializer with no real one-shot guard -- re-init and seize the account | High |
| `eip7702-missing-nonce` | A signed action with no nonce -- replay it at will | High |
| `eip7702-replay-unsafe-sig` | A signature that doesn't bind chainId -- replay it on another chain | Medium |
| `eip7702-unsafe-eoa-assumption` | `tx.origin == msg.sender` used as an "is-EOA" check -- 7702 breaks it | Medium |
| `eip7702-constructor-state` | Security state set in the constructor -- gone the moment an EOA delegates | Medium |
| `eip7702-storage-collision` | Plain (non-namespaced) storage -- re-delegation can corrupt it; use ERC-7201 | Informational |

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

Add the remaining arguments from the table to run the whole pack.

## Where it's headed

The static detectors are done and tested. Next is a set of Foundry harnesses that actually run a
delegate under 7702 conditions -- switching delegates, replaying signatures -- to confirm the
multi-transaction issues (storage contamination especially) dynamically, not just flag them.

High and Medium findings are real bugs worth reviewing. Informational (storage-collision) is a
"prefer ERC-7201" heads-up, not a vulnerability.

MIT licensed.
