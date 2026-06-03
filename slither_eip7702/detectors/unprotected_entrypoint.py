from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnprotectedEntrypoint(AbstractDetector):
    """EIP-7702 delegate exposes an arbitrary-call entrypoint with no caller check.

    Heuristic (v0): a public/external entrypoint that performs a low-level external call
    (call/delegatecall) while NEITHER the function body NOR any of its modifiers reads
    `msg.sender`. Honest limit: it only checks that msg.sender is read *somewhere* (a gate
    exists), not that the comparison is correct (== address(this) / owner). Refine once the
    corpus two-way proof is wired (V0 must fire, the guarded control must stay clean).
    """

    ARGUMENT = "eip7702-unprotected-entrypoint"
    HELP = "EIP-7702 delegate exposes an unprotected arbitrary-call entrypoint"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder until public repo is set
    WIKI_TITLE = "EIP-7702 unprotected entrypoint"
    WIKI_DESCRIPTION = (
        "An EIP-7702 delegate contract exposes a public/external function that makes an "
        "attacker-controlled external call (call/delegatecall) without verifying the caller is "
        "the account itself (msg.sender == address(this)) or an authorized owner. The delegate's "
        "code runs in the EOA's storage/context, so anyone can invoke this entrypoint on a "
        "delegated account and drain it or take it over."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Alice delegates her EOA to a contract whose `execute(address t, bytes d) external` does "
        "`t.call(d)` with no caller check. Any attacker calls Alice's account's execute() and "
        "moves her funds."
    )
    WIKI_RECOMMENDATION = (
        "Gate every execution entrypoint on `require(msg.sender == address(this))` (the account "
        "itself, via a 7702-delegated self-call) or a verified owner / authorization signature."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_entry_points:
                if function.is_constructor or function.is_fallback or function.is_receive:
                    continue
                # only entrypoints that make a low-level external call (call/delegatecall)
                if not function.low_level_calls:
                    continue
                # is the caller checked anywhere -- function body OR a modifier?
                reads = list(function.solidity_variables_read)
                for mod in function.modifiers:
                    reads += list(mod.solidity_variables_read)
                gated = any(getattr(v, "name", "") == "msg.sender" for v in reads)
                if gated:
                    continue
                info = [
                    "EIP-7702 unprotected entrypoint: ",
                    function,
                    " makes an arbitrary external call without checking msg.sender -- any caller "
                    "can drive the delegated account.\n",
                ]
                results.append(self.generate_result(info))
        return results
