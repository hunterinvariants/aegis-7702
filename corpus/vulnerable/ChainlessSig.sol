// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-replay-unsafe-sig` (V3). Has a nonce (so this is NOT the missing-nonce bug),
/// but the digest omits chainId/address(this) -> the signature replays on another chain. MUST fire.
contract ChainlessSig {
    address public owner;
    mapping(uint256 => bool) public usedNonce;

    function exec(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedNonce[nonce], "replayed");
        usedNonce[nonce] = true;
        bytes32 digest = keccak256(abi.encodePacked(to, amount, nonce));
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
