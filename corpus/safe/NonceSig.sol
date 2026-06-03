// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged). Tracks a per-signature nonce -> no replay.
contract NonceSig {
    address public owner;
    mapping(uint256 => bool) public usedNonce;

    function send(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedNonce[nonce], "replayed");
        usedNonce[nonce] = true;
        bytes32 digest = keccak256(abi.encodePacked(to, amount, nonce));
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
