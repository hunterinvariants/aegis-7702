from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsafeEoaAssumption(AbstractDetector):
    """Protocol relies on `tx.origin == msg.sender` to mean 'caller is a plain EOA' -- EIP-7702
    breaks that: a delegated EOA runs contract code while msg.sender == tx.origin.

    Heuristic: flag a function/modifier with a node that COMPARES `tx.origin` and `msg.sender`
    (an `==` / `!=` between them) -- the canonical EOA check. A node that merely reads both without
    comparing them (e.g. `keccak256(abi.encode(tx.origin, msg.sender))`) is NOT the assumption and is
    not flagged.
    """

    ARGUMENT = "eip7702-unsafe-eoa-assumption"
    HELP = "Caller-is-EOA assumption (tx.origin == msg.sender) broken by EIP-7702"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder until public repo is set
    WIKI_TITLE = "EIP-7702 unsafe EOA assumption"
    WIKI_DESCRIPTION = (
        "The contract compares tx.origin to msg.sender to assume the caller is a plain EOA (no code). "
        "Under EIP-7702 a delegated EOA executes contract code while msg.sender == tx.origin, so the "
        "assumption no longer holds: a 7702-delegated account passes the check yet runs arbitrary code, "
        "enabling whitelist bypass / privilege borrowing and the reentrancy the check meant to prevent."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A protocol gates a reward/whitelist with `require(tx.origin == msg.sender)`. A whitelisted EOA "
        "delegates (7702) to a proxy and shares the signed authorization; an attacker drives the protocol "
        "through that account -- the check passes and the attacker borrows the whitelisted privileges."
    )
    WIKI_RECOMMENDATION = (
        "Do not use `tx.origin == msg.sender` (or extcodesize == 0) as an EOA / human check. If you must "
        "reject smart-account callers, detect the EIP-7702 delegation stub (msg.sender.code starting with "
        "0xef0100) and reject delegated accounts explicitly."
    )

    def _detect(self):
        try:
            from slither.slithir.operations import Binary, BinaryType
            _CMP = (BinaryType.EQUAL, BinaryType.NOT_EQUAL)
        except Exception:
            Binary = None
            _CMP = ()
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for scope in list(contract.functions) + list(contract.modifiers):
                hit = False
                for node in scope.nodes:
                    names = {getattr(v, "name", "") for v in node.solidity_variables_read}
                    if "tx.origin" not in names or "msg.sender" not in names:
                        continue
                    # require an actual == / != comparison in this node, not a mere co-read
                    if Binary is None:
                        hit = True  # fallback: cannot introspect IR -> keep prior behavior
                        break
                    for ir in node.irs:
                        if isinstance(ir, Binary) and getattr(ir, "type", None) in _CMP:
                            hit = True
                            break
                    if hit:
                        break
                if hit:
                    info = [
                        "EIP-7702 unsafe EOA assumption: ",
                        scope,
                        " compares tx.origin to msg.sender to assume an EOA caller -- a 7702-delegated "
                        "account passes this yet runs code (whitelist bypass / privilege borrowing).\n",
                    ]
                    results.append(self.generate_result(info))
        return results
