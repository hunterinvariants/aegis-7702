// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Known-BAD for `eip7702-constructor-state` (7702-goat V1 class). `guardian` is set ONLY in the
/// constructor -> when an EOA delegates to this contract, the constructor never runs for the EOA, so
/// `guardian` is address(0) for the delegated account and the guard is void. MUST be flagged.
contract ConstructorGuardian {
    address public guardian;

    constructor(address g) {
        guardian = g;
    }

    function protectedAction() external view returns (bool) {
        require(msg.sender == guardian, "not guardian");
        return true;
    }
}
