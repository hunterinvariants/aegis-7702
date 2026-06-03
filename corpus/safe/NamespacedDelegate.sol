// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged). Uses ERC-7201 namespaced storage (a struct at a fixed slot) -- no
/// plain top-level mutable state variable -> no re-delegation collision.
contract NamespacedDelegate {
    /// @custom:storage-location erc7201:example.delegate
    struct DelegateStorage {
        address owner;
        bool paused;
    }

    bytes32 private constant STORAGE_SLOT =
        0x00000000000000000000000000000000000000000000000000000000000000ff;

    function _s() private pure returns (DelegateStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == _s().owner, "not owner");
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}
