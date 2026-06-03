from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _recovers_signature(f):
    """True if f recovers an ECDSA signer: raw `ecrecover` builtin OR a library .recover/.tryRecover
    (OpenZeppelin ECDSA). Lazy imports so a wrong IR class name can't break the plugin."""
    try:
        from slither.slithir.operations import SolidityCall, InternalCall, LibraryCall, HighLevelCall
    except Exception:
        return False
    for node in f.nodes:
        for ir in node.irs:
            nm = ""
            if isinstance(ir, SolidityCall):
                nm = (getattr(ir.function, "name", "") or "").lower()
            elif isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
                fn = getattr(ir, "function", None)
                nm = (getattr(fn, "name", "") or "").lower() if fn else ""
            if "ecrecover" in nm or nm in ("recover", "tryrecover"):
                return True
    return False


class ReplayUnsafeSig(AbstractDetector):
    """ecrecover/ECDSA.recover over a digest that omits chain/contract binding -> cross-chain replay (V3).

    Heuristic: an entrypoint that recovers a signature but neither reads `block.chainid` nor touches a
    domain-separator-like state var (domain/separator).
    """

    ARGUMENT = "eip7702-replay-unsafe-sig"
    HELP = "Signature digest omits chainId / domain binding -> cross-chain replay"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder
    WIKI_TITLE = "EIP-7702 chain-replayable signature"
    WIKI_DESCRIPTION = (
        "A signature is verified over a digest that binds neither the chain id nor an EIP-712 domain "
        "separator. The same signed message is valid on every chain / deployment, so it can be "
        "replayed against the delegated account on another chain."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An exec signature is `keccak256(abi.encode(args))` with no chainId. The user signs it on "
        "mainnet; an attacker replays the same signature on an L2 where the EOA also delegated."
    )
    WIKI_RECOMMENDATION = (
        "Bind signatures to chain and contract: include block.chainid and address(this) in the digest, "
        "or use an EIP-712 domain separator."
    )

    _DOMAIN = ("domain", "separator")

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for f in contract.functions_entry_points:
                if f.is_constructor or not _recovers_signature(f):
                    continue
                reads_chainid = any(getattr(v, "name", "") == "block.chainid"
                                    for v in f.solidity_variables_read)
                touched = list(f.state_variables_read) + list(f.state_variables_written)
                uses_domain = any(any(k in v.name.lower() for k in self._DOMAIN) for v in touched)
                if reads_chainid or uses_domain:
                    continue
                info = [
                    "EIP-7702 chain-replayable signature: ",
                    f,
                    " recovers a signature whose digest binds neither block.chainid nor an EIP-712 "
                    "domain separator -- it can be replayed on another chain/deployment.\n",
                ]
                results.append(self.generate_result(info))
        return results
