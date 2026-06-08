from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from slither_eip7702.detectors._util import recovers_signature


class MissingNonce(AbstractDetector):
    """A signature-authorized action with no nonce -> replayable against the delegated account (V5).

    Heuristic: an entrypoint that recovers a signature (ecrecover or ECDSA.recover, including when the
    recovery is wrapped in an internal/library helper) but neither reads nor writes a nonce-like state
    var (nonce/used/consumed/seen/executed).
    """

    ARGUMENT = "eip7702-missing-nonce"
    HELP = "Signature-gated action with no nonce is replayable"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/hunterinvariants/aegis-7702"  # placeholder
    WIKI_TITLE = "EIP-7702 missing signature replay protection"
    WIKI_DESCRIPTION = (
        "A function recovers an ECDSA signature to authorize an action but tracks no nonce, so the same "
        "signature can be replayed against the delegated account to repeat the action."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A delegate's `oneTimeSend(...)` checks a recovered signer with no nonce. An attacker re-submits "
        "the same signed message repeatedly, draining the account."
    )
    WIKI_RECOMMENDATION = (
        "Bind every signed action to a per-account nonce that is checked and incremented, and include "
        "the nonce in the signed digest."
    )

    _NONCE = ("nonce", "used", "consumed", "seen", "executed")

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for f in contract.functions_entry_points:
                if f.is_constructor or not recovers_signature(f):
                    continue
                touched = list(f.state_variables_read) + list(f.state_variables_written)
                if any(any(k in v.name.lower() for k in self._NONCE) for v in touched):
                    continue
                info = [
                    "EIP-7702 missing replay protection: ",
                    f,
                    " recovers a signature but tracks no nonce -- it can be replayed against the "
                    "delegated account.\n",
                ]
                results.append(self.generate_result(info))
        return results
