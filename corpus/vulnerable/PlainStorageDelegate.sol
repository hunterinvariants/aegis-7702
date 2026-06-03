// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-storage-collision` (V4). A delegate with plain sequential storage
/// (owner, paused). If the account re-delegates to a different layout the slots collide. MUST fire.
contract PlainStorageDelegate {
    address public owner;
    bool public paused;

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}
