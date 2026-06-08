// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Regression fixture for the transitive `recovers_signature` (Phase C).
///
/// A signature-authorized send with NO nonce and NO chain binding, where the `ecrecover` is wrapped in
/// an internal helper (`_checkSig`) -- the dominant account/AA pattern. The pre-Phase-C detectors only
/// scanned the entrypoint's own IR, so they MISSED this (false negative). The transitive helper now
/// descends into `_checkSig`, so:
///   - eip7702-missing-nonce       FIRES (signature recovered, no nonce -> replayable)
///   - eip7702-replay-unsafe-sig   FIRES (no chainId / domain binding -> cross-chain replay)
///   - eip7702-unprotected-entrypoint must NOT fire: recovering a signature IS a gate, even via helper.
contract HelperWrappedSig {
    address public owner;

    function _checkSig(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view returns (bool) {
        return ecrecover(digest, v, r, s) == owner; // ecrecover behind an internal helper
    }

    function exec(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(to, amount)); // no nonce, no chainId, no domain
        require(_checkSig(digest, v, r, s), "bad sig");
        (bool ok, ) = to.call{value: amount}(""); // low-level call -> unprotected-entrypoint candidate
        require(ok, "send failed");
    }
}
