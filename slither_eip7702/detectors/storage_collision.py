from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StorageCollision(AbstractDetector):
    """Non-namespaced storage in a delegate -> layout collision if the account re-delegates (V4).

    A 7702 account can change its delegate. Two implementations using plain sequential storage with
    different layouts make slot N mean different things -> corruption on switch. ADVISORY
    (INFORMATIONAL): a single-contract scan can't PROVE a collision (needs two versions); it flags the
    non-namespaced-storage RISK pattern, scoped to contracts that actually look like 7702 delegates.

    Heuristic: contract is delegate-shaped (an entrypoint with a low-level call, an ecrecover, or an
    init-like function) AND declares >=1 mutable (non-constant, non-immutable) state variable. ERC-7201
    contracts keep state in a struct at a fixed slot -> no top-level mutable vars -> clean.
    """

    ARGUMENT = "eip7702-storage-collision"
    HELP = "Delegate uses non-namespaced storage (re-delegation collision risk; prefer ERC-7201)"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder
    WIKI_TITLE = "EIP-7702 non-namespaced delegate storage"
    WIKI_DESCRIPTION = (
        "The delegate keeps state in plain sequential storage slots. A 7702 account that later "
        "re-delegates to a different implementation reinterprets those slots under the new layout, "
        "corrupting state. ERC-7201 namespaced storage isolates each implementation's state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An account delegates to DelegateV3 (slot 0 = paused) then re-delegates to DelegateV4 "
        "(slot 0 = init). The old `paused` value is now read as `init`, mis-configuring or locking it."
    )
    WIKI_RECOMMENDATION = (
        "Use ERC-7201 namespaced storage (a struct at a derived fixed slot) so each delegate "
        "implementation's storage cannot collide with another's."
    )

    @staticmethod
    def _is_delegate_shaped(contract):
        try:
            from slither.slithir.operations import SolidityCall
        except Exception:
            SolidityCall = None
        for f in contract.functions_entry_points:
            if f.low_level_calls:
                return True
            nm = f.name.lower()
            if nm == "init" or nm.startswith("initialize") or nm.startswith("execute"):
                return True
            if SolidityCall is not None:
                for node in f.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall) and "ecrecover" in str(getattr(ir.function, "name", "")):
                            return True
        return False

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            plain = [v for v in contract.state_variables
                     if not getattr(v, "is_constant", False) and not getattr(v, "is_immutable", False)]
            if not plain:
                continue
            if not self._is_delegate_shaped(contract):
                continue
            info = [
                "EIP-7702 non-namespaced storage: ",
                contract,
                f" declares {len(plain)} plain storage variable(s) and is delegate-shaped -- if this "
                "account re-delegates to a different implementation the slots can collide. Consider "
                "ERC-7201 namespaced storage.\n",
            ]
            results.append(self.generate_result(info))
        return results
