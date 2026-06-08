"""Shared helpers for the EIP-7702 detectors."""


def recovers_signature(f, _seen=None):
    """True if `f` recovers an ECDSA signer -- raw `ecrecover`, or a `.recover` / `.tryRecover`
    (e.g. OpenZeppelin ECDSA) -- INCLUDING when the recovery is wrapped in an internal/library helper
    (`_verify`, `_checkSig`, ...), the dominant account/AA pattern. Walks the entrypoint's internal and
    library callees transitively; a seen-set prevents recursion loops, and lazy import + getattr guards
    + a broad try/except ensure an unexpected IR shape can never break the plugin (it degrades to False).
    """
    try:
        from slither.slithir.operations import SolidityCall, InternalCall, LibraryCall, HighLevelCall
    except Exception:
        return False
    if _seen is None:
        _seen = set()
    key = getattr(f, "canonical_name", None) or id(f)
    if key in _seen:
        return False
    _seen.add(key)
    try:
        for node in (getattr(f, "nodes", None) or []):
            for ir in node.irs:
                nm = ""
                callee = None
                if isinstance(ir, SolidityCall):
                    nm = (getattr(ir.function, "name", "") or "").lower()
                elif isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
                    callee = getattr(ir, "function", None)
                    nm = (getattr(callee, "name", "") or "").lower() if callee else ""
                if "ecrecover" in nm or nm in ("recover", "tryrecover"):
                    return True
                # descend only into same-codebase helpers (internal / library), not external calls
                if isinstance(ir, (InternalCall, LibraryCall)) and callee is not None \
                        and getattr(callee, "nodes", None):
                    if recovers_signature(callee, _seen):
                        return True
    except Exception:
        return False
    return False


def is_state_changing(f):
    """False for view/pure functions. A signature recovered inside a function that changes no state has
    no action to replay (a view/pure cannot move funds or flip a flag), so the replay/nonce detectors
    should skip it -- otherwise they flag signature-verification primitives like Safe.checkSignatures."""
    try:
        if getattr(f, "pure", False) or getattr(f, "view", False):
            return False
    except Exception:
        pass
    return True


def binds_chain(f, _seen=None):
    """True if `f` binds its signature digest to a chain/domain -- reads `block.chainid`, invokes the
    `chainid()` opcode (commonly via inline assembly in a `getChainId` helper), or touches a
    domain-separator-like state var -- INCLUDING transitively through internal/library helpers
    (Safe computes its digest several calls deep). Mirrors recovers_signature's safe, guarded walk."""
    try:
        from slither.slithir.operations import SolidityCall, InternalCall, LibraryCall
    except Exception:
        return False
    if _seen is None:
        _seen = set()
    key = getattr(f, "canonical_name", None) or id(f)
    if key in _seen:
        return False
    _seen.add(key)
    try:
        for v in (getattr(f, "solidity_variables_read", None) or []):
            if getattr(v, "name", "") == "block.chainid":
                return True
        for v in (list(getattr(f, "state_variables_read", None) or []) +
                  list(getattr(f, "state_variables_written", None) or [])):
            nm = (getattr(v, "name", "") or "").lower()
            if "domain" in nm or "separator" in nm:
                return True
        for node in (getattr(f, "nodes", None) or []):
            for ir in node.irs:
                if isinstance(ir, SolidityCall):
                    if "chainid" in (getattr(ir.function, "name", "") or "").lower():
                        return True
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        if binds_chain(callee, _seen):
                            return True
    except Exception:
        return False
    return False
