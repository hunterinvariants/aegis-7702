// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Control (must NOT be flagged by `eip7702-unsafe-eoa-assumption`).
/// Rejects 7702-delegated callers via the 0xef0100 delegation stub -- the recommended mitigation --
/// instead of the broken `tx.origin == msg.sender` EOA check. Reads msg.sender but never tx.origin.
contract StubCheckGate {
    function _isDelegated(address a) internal view returns (bool) {
        bytes memory c = a.code;
        if (c.length < 3) return false;
        return c[0] == bytes1(0xef) && c[1] == bytes1(0x01) && c[2] == bytes1(0x00);
    }

    function claim() external view returns (bool) {
        require(!_isDelegated(msg.sender), "no delegated accounts");
        return true;
    }
}
