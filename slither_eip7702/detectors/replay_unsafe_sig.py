from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from slither_eip7702.detectors._util import recovers_signature, is_state_changing, binds_chain


class ReplayUnsafeSig(AbstractDetector):
    """ecrecover/ECDSA.recover over a digest that omits chain/contract binding -> cross-chain replay (V3).

    Heuristic: a state-changing entrypoint that recovers a signature (including when the recovery is
    wrapped in an internal/library helper) whose digest is not bound to the chain -- it neither reads
    `block.chainid`, invokes the `chainid()` opcode (incl. via an assembly getChainId helper), nor
    touches a domain-separator-like state var, transitively through its helpers. View/pure functions are
    skipped -- a signature recovered without any state change has no action to replay.
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

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for f in contract.functions_entry_points:
                if f.is_constructor or not recovers_signature(f) or not is_state_changing(f):
                    continue
                if binds_chain(f):
                    continue
                info = [
                    "EIP-7702 chain-replayable signature: ",
                    f,
                    " recovers a signature whose digest binds neither block.chainid nor an EIP-712 "
                    "domain separator -- it can be replayed on another chain/deployment.\n",
                ]
                results.append(self.generate_result(info))
        return results
