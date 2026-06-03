from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RecallableInitializer(AbstractDetector):
    """An external/public function sets ownership/auth state with no working one-shot guard (V2).

    On a 7702 delegate the initializer runs in the EOA's storage and, unguarded, can be called (again)
    by anyone to seize the delegated account. Heuristic: an entrypoint that WRITES an auth-like state
    var (owner/guardian/admin/signer/...) WITHOUT a working one-shot guard. A real guard either uses an
    `initializer`/`reinitializer` modifier, or has a state var that is BOTH read and written (a latch
    set on first call). A flag that is only read but never set (the V2 bug) is NOT a guard.
    """

    ARGUMENT = "eip7702-recallable-initializer"
    HELP = "Unguarded initializer lets anyone (re-)initialize a delegated account"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder
    WIKI_TITLE = "EIP-7702 re-callable initializer"
    WIKI_DESCRIPTION = (
        "An external/public function sets ownership/authorization state with no working one-shot guard "
        "(or a broken one that reads an init flag but never sets it). On a 7702 delegate, anyone can "
        "call it on a delegated account and seize control."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A delegate's `initialize(...)` does `require(!init)` but never sets `init = true`, then writes "
        "guardians. An attacker re-calls initialize() on a delegated account and adds themselves."
    )
    WIKI_RECOMMENDATION = (
        "Use a real one-shot guard: an `initializer` modifier, or a flag that is checked AND set on the "
        "first call (`require(!init); init = true;`)."
    )

    _AUTH = ("owner", "guardian", "admin", "signer", "authority", "root", "operator")

    @staticmethod
    def _has_oneshot_guard(f):
        for m in f.modifiers:
            mn = m.name.lower()
            if "initializ" in mn or "reinitializ" in mn:
                return True
        read = set(f.state_variables_read)
        written = set(f.state_variables_written)
        for m in f.modifiers:
            read |= set(m.state_variables_read)
            written |= set(m.state_variables_written)
        return len(read & written) > 0   # a var read AND written can latch (set-once)

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for f in contract.functions_entry_points:
                if f.is_constructor:
                    continue
                auth_written = [v for v in f.state_variables_written
                                if any(k in v.name.lower() for k in self._AUTH)]
                if not auth_written:
                    continue
                if self._has_oneshot_guard(f):
                    continue
                info = [
                    "EIP-7702 re-callable initializer: ",
                    f,
                    " sets ",
                    auth_written[0],
                    " with no working one-shot guard -- anyone can (re-)initialize the delegated "
                    "account and seize it.\n",
                ]
                results.append(self.generate_result(info))
        return results
