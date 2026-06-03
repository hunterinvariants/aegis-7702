// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged by `eip7702-constructor-state`). `guardian` is set via an initializer
/// the delegated account calls AFTER delegation -- so it persists in the EOA's own storage. No
/// security state is set in a constructor (there is none). The detector must stay clean here.
contract InitializerGuardian {
    address public guardian;
    bool private _init;

    function initialize(address g) external {
        require(!_init, "already init");
        _init = true;
        guardian = g;
    }

    function protectedAction() external view returns (bool) {
        require(msg.sender == guardian, "not guardian");
        return true;
    }
}
