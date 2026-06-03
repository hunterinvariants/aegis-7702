"""slither-eip7702 -- a Slither plugin adding EIP-7702 delegate-contract security detectors.

Slither's core detector set has no EIP-7702-specific checks; this pack adds them. The plugin
entry point (`slither_analyzer.plugin` in setup.py) calls make_plugin(), which returns the
(detectors, printers) tuple Slither expects.
"""
from slither_eip7702.detectors.unprotected_entrypoint import UnprotectedEntrypoint
from slither_eip7702.detectors.unsafe_eoa_assumption import UnsafeEoaAssumption
from slither_eip7702.detectors.constructor_state import ConstructorState
from slither_eip7702.detectors.recallable_initializer import RecallableInitializer
from slither_eip7702.detectors.missing_nonce import MissingNonce
from slither_eip7702.detectors.replay_unsafe_sig import ReplayUnsafeSig
from slither_eip7702.detectors.storage_collision import StorageCollision


def make_plugin():
    plugin_detectors = [
        UnprotectedEntrypoint,      # 1 (V0)
        UnsafeEoaAssumption,        # 7 (protocol-side, Halborn)
        ConstructorState,           # 2 (V1)
        RecallableInitializer,      # 3 (V2)
        MissingNonce,               # 6 (V5)
        ReplayUnsafeSig,            # 4 (V3)
        StorageCollision,           # 5 (V4, INFORMATIONAL advisory)
    ]
    plugin_printers = []
    return plugin_detectors, plugin_printers
