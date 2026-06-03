// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged). `initialize` is guarded against re-init (owner must be unset).
contract GuardedInitializer {
    address public owner;

    function initialize(address newOwner) external {
        require(owner == address(0), "already initialized");
        owner = newOwner;
    }
}
