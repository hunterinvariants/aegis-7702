// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-missing-nonce` (V5). `oneTimeSend` verifies a signature but tracks no
/// nonce -> the signature can be replayed to drain the delegated account. MUST be flagged.
contract NoNonceSig {
    address public owner;

    function oneTimeSend(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
