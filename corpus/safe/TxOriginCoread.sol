// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Regression fixture for the M1 precision fix on eip7702-unsafe-eoa-assumption.
///
/// This contract READS both tx.origin and msg.sender in a single expression but never COMPARES them
/// (no `tx.origin == msg.sender`). It is therefore NOT making the is-EOA assumption, so the detector
/// must stay quiet. The pre-M1 heuristic (fire on any node that reads both) false-fired here; the
/// tightened version (require an actual ==/!= comparison) does not.
contract TxOriginCoread {
    event Seen(address origin, address sender);
    mapping(bytes32 => bool) public seen;

    function record() external {
        bytes32 k = keccak256(abi.encodePacked(tx.origin, msg.sender)); // co-read, NOT a comparison
        seen[k] = true;
        emit Seen(tx.origin, msg.sender);
    }
}
