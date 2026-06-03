from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConstructorState(AbstractDetector):
    """Security state initialized ONLY in a constructor -- never persists under EIP-7702 delegation.

    A 7702 delegate runs the implementation's CODE in the EOA's storage. Constructors ran at the
    implementation's deploy and wrote the implementation's storage, NOT the delegating EOA's. So a
    storage variable set only in a constructor is unset (zero) for every delegated account, voiding any
    guard/owner/config relying on it. Initialize in an initializer the account calls after delegating.

    Heuristic: a non-constant, non-immutable state variable written in ANY constructor (the contract's
    own or an inherited base's) and in NO non-constructor function. (immutables/constants live in code
    -> persist -> excluded.) Honest limit: assumes the contract is used as a 7702 delegate.
    """

    ARGUMENT = "eip7702-constructor-state"
    HELP = "Security state set only in the constructor does not persist under EIP-7702 delegation"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder
    WIKI_TITLE = "EIP-7702 constructor-set state does not persist"
    WIKI_DESCRIPTION = (
        "A storage variable initialized only in a constructor is never set for an account that "
        "delegates to this contract via EIP-7702: the constructor ran against the implementation's "
        "storage at deploy time, not the EOA's. Any owner/guardian/config guard relying on it is void."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A delegate sets `guardians` in its constructor. Alice delegates her EOA to it; her account's "
        "`guardians` storage is empty, so the guardian guard is void / the account is mis-initialized."
    )
    WIKI_RECOMMENDATION = (
        "Initialize storage in an `initialize()` the account calls AFTER delegating (guarded against "
        "re-init), not in the constructor. Constructor-set immutables/constants are fine (they live in code)."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            ctors = [f for f in contract.functions if f.is_constructor]
            if not ctors:
                continue
            ctor_written = set()
            for cf in ctors:
                ctor_written |= set(cf.state_variables_written)
            written_elsewhere = set()
            for f in contract.functions:
                if f.is_constructor:
                    continue
                written_elsewhere |= set(f.state_variables_written)
            for var in sorted(ctor_written, key=lambda v: v.name):
                if getattr(var, "is_constant", False) or getattr(var, "is_immutable", False):
                    continue
                if var in written_elsewhere:
                    continue
                info = [
                    "EIP-7702 constructor-only state: ",
                    var,
                    " is set only in a constructor of ",
                    contract,
                    " -- it will be zero for any account that delegates to this contract (the "
                    "constructor never runs for the delegating EOA). Initialize it in a guarded "
                    "initializer instead.\n",
                ]
                results.append(self.generate_result(info))
        return results
