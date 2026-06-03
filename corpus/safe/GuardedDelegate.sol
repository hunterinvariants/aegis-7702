// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged by `eip7702-unprotected-entrypoint`).
/// Same arbitrary-call entrypoint, but gated on `msg.sender == address(this)` -- only the account
/// itself (via a 7702-delegated self-call) can drive it. The detector must stay clean here.
contract GuardedDelegate {
    function execute(address target, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        require(msg.sender == address(this), "only self");
        (bool ok, bytes memory ret) = target.call{value: msg.value}(data);
        require(ok, "call failed");
        return ret;
    }
}
