# Aegis-7702 Detectors

Each detector targets a failure mode that only appears once a contract runs as an EIP-7702 delegate --
in the EOA's own storage and calling context. The examples below are minimal; `corpus/` holds a
vulnerable and a safe case for every detector, and the full set is validated against
`theredguild/7702-goat`. Severity reflects impact under delegation. Detectors are heuristics: review
each finding in context.

---

## eip7702-unprotected-entrypoint (High)

**Description.** A public/external function makes an arbitrary external call (`call`/`delegatecall`)
without checking the caller. Delegated into an EOA, the code runs as that account, so any address can
invoke the entrypoint and move the account's funds.

Vulnerable:

    function execute(address target, bytes calldata data) external {
        target.call(data);            // no caller check
    }

**Recommendation.** Gate execution on the account itself (or a verified owner):

    require(msg.sender == address(this), "only self");

---

## eip7702-recallable-initializer (High)

**Description.** An initializer sets ownership/authorization state with no working one-shot guard. A
guard that reads a flag but never sets it -- or no guard at all -- lets anyone call the initializer on
a delegated account and take it over.

Vulnerable:

    function initialize(address[] calldata guardians) external {
        require(!initialized);        // bug: never sets initialized = true
        for (uint256 i; i < guardians.length; i++) guardian[guardians[i]] = true;
    }

**Recommendation.** Use a real one-shot guard -- an `initializer` modifier, or check *and set* the flag:

    require(!initialized); initialized = true;

---

## eip7702-missing-nonce (High)

**Description.** A signature-authorized action (verified with `ecrecover` or a library `ECDSA.recover`)
tracks no nonce, so the same signed message can be replayed against the delegated account to repeat the
action -- for example, to drain it.

Vulnerable:

    function send(address to, uint256 amt, uint8 v, bytes32 r, bytes32 s) external {
        require(ECDSA.recover(keccak256(abi.encode(to, amt)), v, r, s) == owner);
        to.call{value: amt}("");      // no nonce -> replayable
    }

**Recommendation.** Bind each signed action to a per-account nonce that is checked and incremented, and
include the nonce in the signed digest.

---

## eip7702-replay-unsafe-sig (Medium)

**Description.** A signature is verified over a digest that binds neither the chain id nor an EIP-712
domain separator. The same signature is valid on every chain and deployment, so it can be replayed
against the account on another chain where the same EOA delegated.

Vulnerable:

    bytes32 digest = keccak256(abi.encode(newGuardians, address(this)));  // no chainId
    require(ECDSA.recover(digest, v, r, s) == owner);

**Recommendation.** Include `block.chainid` (and `address(this)`) in the digest, or use an EIP-712
domain separator.

---

## eip7702-unsafe-eoa-assumption (Medium)

**Description.** Code uses `tx.origin == msg.sender` to assume the caller is a plain EOA. Under
EIP-7702 a delegated EOA runs contract code while `msg.sender == tx.origin`, so a smart account passes
the check -- breaking the whitelist or reentrancy assumption that relied on it.

Vulnerable:

    require(tx.origin == msg.sender, "EOAs only");

**Recommendation.** Do not use this as an is-EOA check. If you must reject delegated callers, detect the
7702 delegation stub: `msg.sender.code` beginning with `0xef0100`.

---

## eip7702-constructor-state (Medium)

**Description.** Security state (owner, guardians, config) is set only in a constructor. A constructor
runs at the implementation's deployment, against the implementation's storage -- never the delegating
EOA's. So for every delegated account that state reads as zero, and any guard relying on it is void.

Vulnerable:

    constructor(address g) { guardian = g; }   // guardian is 0 for every delegated account

**Recommendation.** Set state in an initializer the account calls after delegating (guarded against
re-init). Constructor-set `immutable`/`constant` values are fine -- they live in code, not storage.

---

## eip7702-storage-collision (Informational)

**Description.** A delegate keeps state in plain, sequential storage slots. An account can re-delegate
to a different implementation; if the two layouts differ, slot N means different things to each, and
the old value is reinterpreted by the new code -- corrupting state. A single-contract scan cannot prove
a collision (that needs two implementations), so this is a hardening advisory, scoped to contracts that
look like delegates.

Vulnerable:

    bool public paused;    // slot 0
    address public owner;  // slot 1  -- a different delegate may map these slots differently

**Recommendation.** Use ERC-7201 namespaced storage (a struct at a derived fixed slot) so each
implementation's storage cannot collide with another's.
