// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-unsafe-eoa-assumption`. Gates on `tx.origin == msg.sender` to mean
/// "caller is an EOA" -- a 7702-delegated account passes this yet runs code. MUST be flagged.
contract TxOriginGate {
    mapping(address => bool) public whitelisted;

    function claim() external view returns (bool) {
        require(tx.origin == msg.sender, "no contracts");
        return whitelisted[msg.sender];
    }
}
