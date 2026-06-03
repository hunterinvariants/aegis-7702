// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-recallable-initializer` (V2). `initialize` sets `owner` with no re-init
/// guard -> any attacker can re-initialize a delegated account and seize it. MUST be flagged.
contract OpenInitializer {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }
}
