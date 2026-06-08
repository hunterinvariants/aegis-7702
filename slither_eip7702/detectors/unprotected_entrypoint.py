from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from slither_eip7702.detectors._util import recovers_signature


class UnprotectedEntrypoint(AbstractDetector):
    """EIP-7702 delegate exposes an arbitrary-call entrypoint with no caller check.

    Heuristic: a public/external entrypoint that performs a low-level external call (call/delegatecall)
    while the caller is gated by NEITHER of the two authorization shapes a 7702 delegate can use:
      (1) `msg.sender` is read in the function body or a modifier (an address gate), OR
      (2) the function recovers an ECDSA signature (a signature gate) -- raw `ecrecover` or
          `ECDSA.recover`, including when wrapped in an internal/library helper (see `_util`).
    Honest limit: it checks that *a* gate exists, not that the comparison is correct
    (== address(this) / owner). V0 (no gate at all) must fire; the signature- and address-guarded
    controls must stay clean.
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
                # a signature gate (ecrecover / ECDSA.recover, incl. helper-wrapped) also authorizes
                if not gated and recovers_signature(function):
                    gated = True
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
