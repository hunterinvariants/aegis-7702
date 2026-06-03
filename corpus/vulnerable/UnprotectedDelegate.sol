// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD corpus case for `eip7702-unprotected-entrypoint` (7702-goat V0 class).
/// An EIP-7702 delegate target whose `execute` makes an arbitrary external call with NO caller
/// check. Delegated into an EOA, anyone can call it and drain the account. MUST be flagged.
contract UnprotectedDelegate {
    function execute(address target, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: msg.value}(data);
        require(ok, "call failed");
        return ret;
    }
}
